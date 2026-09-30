#!/usr/bin/env bash
# carry-over-preflight.sh — READ-ONLY check before carrying legacy Socrate data into the new one.
# Run as root on the Socrate VPS, with the same APPS / EXCLUDE_USERS you will give carry-over.sh:
#
#   sudo bash carry-over-preflight.sh
#   sudo APPS=<client_id>[,…] EXCLUDE_USERS=<legacy id>[,…] bash carry-over-preflight.sh
#
# carry-over.sh copies users, apps and user_app_roles with their primary keys and
# ON CONFLICT DO NOTHING. That is only safe when the target holds no row whose id or unique key
# collides with a different legacy row:
#   - a skipped legacy user whose id is taken hands that id's `sub` to someone else;
#   - a legacy user whose email is taken under another id loses its `sub`;
#   - a skipped legacy app whose id is taken makes its role rows attach to the wrong app.
# It also checks that new ids are reserved clear of the legacy ranges (reserve-legacy-ids.sh).
# It writes nothing (SELECTs only, no files) and prints emails masked.
#
# Env: OLD_DB (default db_socrate), NEW_DB (default socrate), APPS (default ALL),
#      EXCLUDE_USERS (legacy ids not to carry), PSQL (default: sudo -u postgres psql).
set -euo pipefail
OLD_DB="${OLD_DB:-db_socrate}"
NEW_DB="${NEW_DB:-socrate}"
APPS="${APPS:-ALL}"
EXCLUDE_USERS="${EXCLUDE_USERS:-}"
PSQL="${PSQL:-sudo -u postgres psql}"
cd / # psql run through sudo -u postgres cannot read the caller's home directory

q() { $PSQL -X -q -At -F'|' -v ON_ERROR_STOP=1 "$1" -c "$2"; }
mask() { awk -F'|' -v OFS='|' '{ for (i = 1; i <= NF; i++) if ($i ~ /@/) { split($i, a, "@"); $i = substr(a[1], 1, 1) "***@" a[2] } print }'; }
bad=0
hdr() { printf '\n\033[1m▶ %s\033[0m\n' "$*"; }
ok()  { printf '  \033[32m✔\033[0m %s\n' "$*"; }
nok() { printf '  \033[31m✖\033[0m %s\n' "$*"; bad=1; }
warn(){ printf '  \033[33m⚠\033[0m %s\n' "$*"; }
info(){ printf '  · %s\n' "$*"; }

[[ -z "$EXCLUDE_USERS" || "$EXCLUDE_USERS" =~ ^[0-9]+(,[0-9]+)*$ ]] || { echo "EXCLUDE_USERS must be comma-separated numeric ids" >&2; exit 2; }
[[ "$APPS" == ALL || "$APPS" =~ ^[A-Za-z0-9_.,-]+$ ]] || { echo "APPS must be ALL or comma-separated client_ids" >&2; exit 2; }
for db in "$OLD_DB" "$NEW_DB"; do
  [ "$(q postgres "SELECT count(*) FROM pg_database WHERE datname='$db'")" = 1 ] || { echo "database $db not found (set OLD_DB/NEW_DB)" >&2; exit 2; }
done
has_col() { [ "$(q "$1" "SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='$2' AND column_name='$3'")" = 1 ]; }
live() { has_col "$1" users deleted_at && echo "deleted_at IS NULL" || echo "true"; }

# The legacy rows the carry-over would select (same filters as carry-over.sh).
if [[ "$APPS" == ALL ]]; then APP_F="true"; USER_F="true"
else
  IN="'${APPS//,/\',\'}'"
  APP_F="client_id IN ($IN)"
  USER_F="(id IN (SELECT user_id FROM user_app_roles WHERE app_id IN (SELECT id FROM apps WHERE $APP_F)) OR id IN (SELECT owner_id FROM apps WHERE $APP_F AND owner_id IS NOT NULL))"
fi
[[ -n "$EXCLUDE_USERS" ]] && USER_F="$USER_F AND id NOT IN ($EXCLUDE_USERS)"

hdr "databases"
for db in "$OLD_DB" "$NEW_DB"; do
  info "$db: users $(q "$db" "SELECT count(*) FROM users WHERE $(live "$db")") live / $(q "$db" "SELECT count(*) FROM users") total, apps $(q "$db" "SELECT count(*) FROM apps"), user_app_roles $(q "$db" "SELECT count(*) FROM user_app_roles")"
done
info "selection: APPS=$APPS${EXCLUDE_USERS:+, EXCLUDE_USERS=$EXCLUDE_USERS}"
[[ "$APPS" != ALL ]] && for c in ${APPS//,/ }; do
  [ "$(q "$OLD_DB" "SELECT count(*) FROM apps WHERE client_id='$c'")" = 1 ] || nok "client_id $c is not in $OLD_DB"
done

# In-memory lists (never written to disk). NEW ids include deleted rows: they still hold the id.
OLD_U="$(q "$OLD_DB" "SELECT id, lower(email) FROM users WHERE $USER_F ORDER BY id")"
NEW_ALL="$(q "$NEW_DB" "SELECT id, lower(email), CASE WHEN $(live "$NEW_DB") THEN 'live' ELSE 'retired' END FROM users ORDER BY id")"
OLD_A="$(q "$OLD_DB" "SELECT a.id, a.client_id, a.name, (SELECT count(*) FROM user_app_roles r WHERE r.app_id=a.id) FROM apps a WHERE $APP_F ORDER BY a.id")"
NEW_A="$(q "$NEW_DB" "SELECT a.id, a.client_id, a.name, (SELECT count(*) FROM user_app_roles r WHERE r.app_id=a.id) FROM apps a ORDER BY a.id")"

hdr "users to carry: $(grep -c . <<<"$OLD_U" || true) (a legacy user's id is its sub; it must land on the same id)"
same=0; ubad=0
while IFS='|' read -r oid oemail; do
  [ -n "$oid" ] || continue
  hit="$(awk -F'|' -v id="$oid" '$1==id' <<<"$NEW_ALL")"
  if [ -n "$hit" ]; then
    nemail="$(cut -d'|' -f2 <<<"$hit")"; state="$(cut -d'|' -f3 <<<"$hit")"
    if [ "$nemail" = "$oemail" ] && [ "$state" = live ]; then same=$((same+1)); info "id $oid: same person already there ($(mask <<<"$oemail")) — skipped, identity kept"
    else ubad=1; nok "id $oid is taken in $NEW_DB by $( [ "$state" = retired ] && echo 'a RETIRED row' || echo "$(mask <<<"$nemail")") — legacy $(mask <<<"$oemail") would be skipped (exclude it, or free the id)"; fi
    continue
  fi
  nid="$(awk -F'|' -v e="$oemail" '$2==e && $3=="live"{print $1}' <<<"$NEW_ALL")"
  if [ -n "$nid" ]; then ubad=1; nok "$(mask <<<"$oemail") is user $nid in $NEW_DB but $oid in legacy — the carry would skip it and its sub would change (move-user-to-legacy-id.sh --to $oid)"; fi
done <<<"$OLD_U"
[ "$ubad" = 0 ] && ok "no user collision ($same already present as the same person)"

hdr "apps to carry: $(grep -c . <<<"$OLD_A" || true)"
abad=0
while IFS='|' read -r oid ocid oname _; do
  [ -n "$oid" ] || continue
  hit="$(awk -F'|' -v id="$oid" '$1==id' <<<"$NEW_A")"
  if [ -n "$hit" ] && [ "$(cut -d'|' -f2 <<<"$hit")" != "$ocid" ]; then abad=1; nok "app id $oid ('$oname') is taken in $NEW_DB by '$(cut -d'|' -f3 <<<"$hit")' — the legacy app would be skipped and its roles would attach to that app"; fi
  nid="$(awk -F'|' -v c="$ocid" '$2==c{print $1}' <<<"$NEW_A")"
  if [ -n "$nid" ] && [ "$nid" != "$oid" ]; then abad=1; nok "client_id $ocid is app $nid in $NEW_DB but $oid in legacy"; fi
  info "id $oid  $ocid  '$oname'"
done <<<"$OLD_A"
[ "$abad" = 0 ] && ok "no app collision"
if [[ -n "$EXCLUDE_USERS" ]]; then
  o="$(q "$OLD_DB" "SELECT string_agg(name, ', ') FROM apps WHERE $APP_F AND owner_id IN ($EXCLUDE_USERS)")"
  [ -n "$o" ] && info "owned by an excluded user, will be carried with no owner: $o"
fi

hdr "id reservation (new ids must stay clear of the legacy ranges)"
for tbl in users apps user_app_roles; do
  seq="$(q "$NEW_DB" "SELECT pg_get_serial_sequence('$tbl','id')")"; [ -n "$seq" ] || continue
  old_max="$(q "$OLD_DB" "SELECT COALESCE(MAX(id),0) FROM $tbl")"
  next="$(q "$NEW_DB" "SELECT CASE WHEN is_called THEN last_value + 1 ELSE last_value END FROM $seq")"
  if [ "$next" -gt "$old_max" ]; then ok "$tbl: next new id $next > legacy max $old_max"
  else warn "$tbl: next new id $next ≤ legacy max $old_max — run reserve-legacy-ids.sh --apply before creating anything on the new server"; fi
done

hdr "things the copy cannot carry as-is"
if has_col "$OLD_DB" users mfa_enabled; then
  m="$(q "$OLD_DB" "SELECT count(*) FROM users WHERE $USER_F AND mfa_enabled")"
  if [ "$m" -gt 0 ]; then warn "$m user(s) have MFA: the TOTP secret is encrypted with the LEGACY SECRET_KEY_BASE and will not decrypt on the new server — they must re-enrol"
  else ok "no selected user has MFA enabled"; fi
else ok "legacy schema has no MFA column"; fi
info "not carried by design: refresh tokens and sessions (everyone signs in once), the audit history (stays in $OLD_DB)"

printf '\n'
if [ "$bad" = 0 ]; then printf '\033[32mNo collision: carry-over.sh can run with these settings (rehearse on a *_test copy first).\033[0m\n'
else printf '\033[31mCollisions found: do NOT run carry-over.sh with these settings. Send this output (emails are masked).\033[0m\n'; fi
