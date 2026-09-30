#!/usr/bin/env bash
# carry-over.sh — ID-preserving data migration for the Socrate strangler-fig move.
#
# Copies users, apps and user_app_roles (in that FK order) from the OLD Socrate database (schema at an
# earlier migration, e.g. 0005) into the NEW v1.3.0 database (schema 0024),
# PRESERVING primary keys. Because a Socrate access token's `sub` is the user's
# numeric id, preserving users.id keeps every subject identical, so relying-party
# apps that match users by `sub` keep working with no remap.
#
# Design notes:
#   * Column-intersection copy. The two schemas differ (0006..0024 add columns), so
#     only columns present in BOTH tables are copied; new columns take their DEFAULTs.
#   * Idempotent. Rows are inserted with ON CONFLICT DO NOTHING, so re-running (or
#     migrating a second app whose users overlap) never duplicates or errors.
#   * Per-app or all. APPS=client_id[,client_id...] migrates only those clients and
#     their users/roles; APPS=ALL migrates everything.
#   * Safe by default. Refuses a NEW_DB that does not look like a test copy unless
#     FORCE=1 — always dry-run against a restored copy first.
#   * A target that is not empty (the new server already has its own users and apps) needs
#     care: a legacy row whose id or email is taken there is skipped silently. Run
#     carry-over-preflight.sh first; it names every such collision. The companions are
#     reserve-legacy-ids.sh (keep new ids clear of the legacy ranges) and
#     move-user-to-legacy-id.sh (give a person created on the new server their legacy id).
#   * Id sequences are only ever moved forward (never below a reservation).
#
# Usage:
#   # 1) test on a copy first (recommended):
#   OLD_DB=db_socrate NEW_DB=db_socrate_new_test APPS=ascenda-web ./carry-over.sh
#   # 2) then the real target:
#   FORCE=1 OLD_DB=db_socrate NEW_DB=db_socrate_v13 APPS=ascenda-web ./carry-over.sh
#
# Env:
#   OLD_DB              source database (default: db_socrate)
#   NEW_DB              target database (required)
#   APPS               ALL, or comma-separated client_ids (default: ALL)
#   SET_REQUIRE_PKCE   1 to set require_pkce=true on migrated apps (default: 1)
#   EXCLUDE_USERS      comma-separated legacy user ids NOT to carry (obsolete accounts): they,
#                      and their role rows, are skipped; an app they own is carried with no owner
#   FORCE              1 to allow a NEW_DB whose name does not end in _test
#   PSQL_SUPER         how to run psql as a superuser (default: sudo -u postgres psql)
set -euo pipefail

OLD_DB="${OLD_DB:-db_socrate}"
NEW_DB="${NEW_DB:?set NEW_DB to the target database (test on a *_test copy first)}"
APPS="${APPS:-ALL}"
SET_REQUIRE_PKCE="${SET_REQUIRE_PKCE:-1}"
FORCE="${FORCE:-0}"
EXCLUDE_USERS="${EXCLUDE_USERS:-}"
if [[ -n "$EXCLUDE_USERS" && ! "$EXCLUDE_USERS" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
	echo "EXCLUDE_USERS must be comma-separated numeric ids" >&2
	exit 2
fi
PSQL_SUPER="${PSQL_SUPER:-sudo -u postgres psql}"

if [[ "$NEW_DB" != *_test && "$FORCE" != "1" ]]; then
	echo "REFUSING: NEW_DB=$NEW_DB does not end in _test. Test on a copy first," >&2
	echo "then re-run with FORCE=1 to target the real database." >&2
	exit 2
fi

sup() { $PSQL_SUPER -X -q -v ON_ERROR_STOP=1 "$1" "${@:2}"; }

# Build the app/user/role filters from APPS.
if [[ "$APPS" == "ALL" ]]; then
	APP_WHERE=""; UAR_WHERE=""; USER_WHERE=""
	echo "==> Migrating ALL apps and users from $OLD_DB -> $NEW_DB"
else
	INLIST="'${APPS//,/\',\'}'"                     # a,b -> 'a','b'
	APP_WHERE="WHERE client_id IN ($INLIST)"
	UAR_WHERE="WHERE app_id IN (SELECT id FROM apps WHERE client_id IN ($INLIST))"
	# Users holding a role in the selected apps, plus each selected app's owner
	# (apps.owner_id is a foreign key to users).
	USER_WHERE="WHERE id IN (SELECT user_id FROM user_app_roles WHERE app_id IN (SELECT id FROM apps WHERE client_id IN ($INLIST))) OR id IN (SELECT owner_id FROM apps WHERE client_id IN ($INLIST) AND owner_id IS NOT NULL)"
	echo "==> Migrating apps [$APPS] and their users from $OLD_DB -> $NEW_DB"
fi

# Obsolete legacy accounts: not carried, nor their roles; apps they own lose the owner.
APP_STAGE_FIX=""
if [[ -n "$EXCLUDE_USERS" ]]; then
	if [[ -z "$USER_WHERE" ]]; then USER_WHERE="WHERE id NOT IN ($EXCLUDE_USERS)"
	else USER_WHERE="WHERE id NOT IN ($EXCLUDE_USERS) AND (${USER_WHERE#WHERE })"; fi
	if [[ -z "$UAR_WHERE" ]]; then UAR_WHERE="WHERE user_id NOT IN ($EXCLUDE_USERS)"
	else UAR_WHERE="$UAR_WHERE AND user_id NOT IN ($EXCLUDE_USERS)"; fi
	APP_STAGE_FIX="UPDATE _stage SET owner_id = NULL WHERE owner_id IN ($EXCLUDE_USERS)"
	echo "==> Excluding legacy users [$EXCLUDE_USERS] and their roles"
fi

# Columns present in BOTH databases for a table, comma-joined. Sorted with LC_ALL=C
# on both sides so comm sees the same order regardless of database collation.
cols_of() {
	sup "$1" -tAc "SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name='$2'" | LC_ALL=C sort
}
shared_cols() {
	LC_ALL=C comm -12 <(cols_of "$OLD_DB" "$1") <(cols_of "$NEW_DB" "$1") | paste -sd, -
}

# Stream rows OLD -> NEW through a pipe (no temp files, so no credential hashes on
# disk and no permission issues with \copy running as the postgres OS user). The
# NEW side stages into a session temp table, then inserts with ON CONFLICT DO
# NOTHING so existing ids are skipped.
copy_table() {
	local tbl="$1" where="$2" fix="${3:-SELECT 1}" cols n res
	cols="$(shared_cols "$tbl")"
	if [[ -z "$cols" ]]; then echo "  !! $tbl: no shared columns" >&2; return 1; fi
	n="$(sup "$OLD_DB" -tAc "SELECT count(*) FROM $tbl $where")"
	echo "  $tbl: $n row(s) selected in OLD; shared columns = $cols"
	res="$(sup "$OLD_DB" -c "\copy (SELECT $cols FROM $tbl $where) TO STDOUT WITH (FORMAT csv)" \
		| $PSQL_SUPER -X -v ON_ERROR_STOP=1 "$NEW_DB" \
			-c "CREATE TEMP TABLE _stage AS SELECT $cols FROM $tbl WHERE false" \
			-c "\copy _stage ($cols) FROM pstdin WITH (FORMAT csv)" \
			-c "$fix" \
			-c "INSERT INTO $tbl ($cols) SELECT $cols FROM _stage ON CONFLICT DO NOTHING")"
	echo "    ${res##*$'\n'} (rows already present were skipped)"
}

# FK order: users (apps.owner_id -> users), then apps, then the join table.
echo "-- copying --"
copy_table users           "$USER_WHERE"
copy_table apps            "$APP_WHERE" "${APP_STAGE_FIX:-SELECT 1}"
copy_table user_app_roles  "$UAR_WHERE"

# Move id sequences past the carried ids so new sign-ups on the new OP do not collide with
# them. Never move one backwards: reserve-legacy-ids.sh may have put it past the legacy ranges.
echo "-- advancing sequences --"
for tbl in apps users user_app_roles; do
	seq="$(sup "$NEW_DB" -tAc "SELECT pg_get_serial_sequence('$tbl','id')")"
	if [[ -n "$seq" ]]; then
		sup "$NEW_DB" -tAc "SELECT setval('$seq', GREATEST(COALESCE((SELECT MAX(id) FROM $tbl),1), (SELECT CASE WHEN is_called THEN last_value ELSE last_value - 1 END FROM $seq), 1), true)" >/dev/null
		echo "  $tbl: sequence at least MAX(id)"
	fi
done

# Normalise columns the old schema lacks. On a FRESH v1.3.0 install these are created
# by the ORM as nullable with no default, so carried rows would get NULL — a state the
# app never writes (its JSONB types always store '{}'). Set them to the values the
# in-place upgrade migrations (0014..0017) would have produced.
echo "-- normalising new columns to upgrade-path defaults --"
sup "$NEW_DB" \
	-c "UPDATE apps SET allowed_scopes = COALESCE(allowed_scopes, '{}'), audiences = COALESCE(audiences, '{}'), claim_mappings = COALESCE(claim_mappings, '{}'::jsonb) WHERE allowed_scopes IS NULL OR audiences IS NULL OR claim_mappings IS NULL" \
	-c "UPDATE users SET attributes = '{}'::jsonb WHERE attributes IS NULL"

# Enforce PKCE on migrated apps (carried require_pkce defaults to false at 0005->0024).
# Gate this behind the compatibility audit: only enable for apps confirmed to use PKCE.
if [[ "$SET_REQUIRE_PKCE" == "1" ]]; then
	echo "-- enforcing PKCE on migrated apps (SET_REQUIRE_PKCE=1) --"
	pkce_where=""
	[[ "$APPS" != "ALL" ]] && pkce_where="AND client_id IN ($INLIST)"
	sup "$NEW_DB" -c "UPDATE apps SET require_pkce=true WHERE require_pkce=false $pkce_where"
	echo "  WARNING: this rejects non-PKCE authorize requests from these clients."
	echo "  Confirm each app implements PKCE (its compat report) before relying on it."
fi

echo "-- verification (row counts in $NEW_DB) --"
for tbl in apps users user_app_roles; do
	printf '  %-16s %s\n' "$tbl" "$(sup "$NEW_DB" -tAc "SELECT count(*) FROM $tbl")"
done
echo "==> done. Next: register/verify the client's redirect URI and scopes, then run the app's test plan."
