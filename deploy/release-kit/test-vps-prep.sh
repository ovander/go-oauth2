#!/usr/bin/env bash
# test-vps-prep.sh - run socrate-vps-prep.sh against a fake root (PREP_ROOT) with stub apt,
# Postgres, Caddy, systemd and user commands; check the plan, the files it writes, that a second
# run changes nothing, that socrate-caddy-update.sh accepts the Caddy sites it writes, and the
# backup script's result line. The prep itself runs unprivileged; the updater and the backup
# script check for root, so run this as root or with passwordless sudo, as on CI runners.
#
#   bash deploy/release-kit/test-vps-prep.sh
# shellcheck disable=SC2016,SC2015 # the stubs are written literally on purpose; pass() never fails
set -euo pipefail

KIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREP="$KIT_DIR/socrate-vps-prep.sh"
SUDO=""; [ "$(id -u)" = 0 ] || SUDO="sudo"
T="$(mktemp -d)"; trap '$SUDO rm -rf "$T"' EXIT
fails=0
pass() { printf '  [ok] %s\n' "$*"; }
fail() { printf '  [FAIL] %s\n' "$*"; fails=$((fails + 1)); }
show() { sed 's/^/      /' "$1"; }
PLACEHOLDER=CHANGE_ME_AFTER_CLIENT_REGISTRATION
OP=op.example.test ADM=admin.example.test MON=monitor.example.test

# ---- stubs ----------------------------------------------------------------------------
# $T/stub: always on PATH. $T/stub-caddy: on PATH when Caddy counts as installed.
# $T/state/fresh present: no package is installed and no Postgres cluster exists.
STUB="$T/stub"; STUBC="$T/stub-caddy"; STATE="$T/state"; LOG="$T/calls.log"
mkdir -p "$STUB" "$STUBC" "$STATE"
stub() { # name body
  printf '#!/bin/sh\n%s\n' "$2" > "$STUB/$1"; chmod +x "$STUB/$1"
}
for c in apt-get curl useradd chown sshd; do stub "$c" "echo \"$c \$*\" >> '$LOG'"; done
stub useradd "echo \"useradd \$*\" >> '$LOG'; for a; do u=\"\$a\"; done; echo \"\$u\" >> '$STATE/users'"
stub dpkg-query "[ -f '$STATE/fresh' ] && exit 1; echo 'install ok installed'"
stub pg_lsclusters "[ -f '$STATE/fresh' ] && exit 0; echo '16 main 5432 online postgres /var/lib/postgresql/16/main /var/log/postgresql/postgresql-16-main.log'"
stub getent 'case "$1" in
  passwd) [ -f '"'$STATE/users'"' ] && grep -qx "$2" '"'$STATE/users'"';;
  group) exit 2;;
  *) exit 0;;
esac'
stub systemctl "case \"\$1\" in is-enabled|is-active) exit 0;; esac; echo \"systemctl \$*\" >> '$LOG'"
stub ufw "case \"\$1\" in status) echo 'Status: inactive';; *) echo \"ufw \$*\" >> '$LOG';; esac"
stub sshd 'echo "port 2222"'
# runuser -u postgres -- psql|pg_dump ...: a tiny fake of the queries the prep and the backup
# script make. CREATE ROLE records the password, so the test can compare it with socrate.env.
stub runuser 'while [ "$1" != "--" ]; do shift; done; shift
cmd="$1"; shift
[ "$cmd" = pg_dump ] && { echo "pg_dump $*" >> '"'$LOG'"'; echo "-- PostgreSQL database dump"; exit 0; }
sql=""
while [ $# -gt 0 ]; do [ "$1" = -c ] && { sql="$2"; shift; }; shift; done
[ -n "$sql" ] || sql="$(cat)"
case "$sql" in
  *"CREATE ROLE"*) echo "$sql" | sed -nE "s/.*PASSWORD '"'"'([^'"'"']*)'"'"'.*/\1/p" > '"'$STATE/role-pw'"'; touch '"'$STATE/role'"'; echo "runuser CREATE ROLE" >> '"'$LOG'"';;
  *"CREATE DATABASE"*) touch '"'$STATE/db'"'; echo "runuser CREATE DATABASE" >> '"'$LOG'"';;
  *"FROM pg_roles"*) [ -f '"'$STATE/role'"' ] && echo 1;;
  "SELECT 1 FROM pg_database"*) [ -f '"'$STATE/db'"' ] && echo 1;;
  *pg_get_userbyid*) echo socrate;;
  *server_version_num*) echo 160004;;
  *to_regclass*) echo t;;
  *"FROM schema_migrations"*) echo 31;;
esac
exit 0'
stub psql "[ -f '$STATE/role-pw' ] && [ \"\$PGPASSWORD\" = \"\$(cat '$STATE/role-pw')\" ] && echo 1"
printf '#!/bin/sh\ncase "$1" in version) echo "v2.10.2 h1:x";; *) echo "caddy $*" >> %s;; esac\n' "'$LOG'" > "$STUBC/caddy"
chmod +x "$STUBC/caddy"

ROOT="$T/root"
os_release() { mkdir -p "$ROOT/etc"; printf 'ID=ubuntu\nVERSION_ID="%s"\nVERSION_CODENAME=%s\n' "$1" "$2" > "$ROOT/etc/os-release"; }
prep() { # [args] -> output in $T/out, exit code in $rc; the calls of this run in $T/calls
  rc=0; : > "$LOG"
  env PATH="$STUB:$STUBC:$CLEAN_PATH" PREP_ROOT="$ROOT" OP_HOST="$OP" ADMIN_HOST="$ADM" MON_HOST="$MON" \
    bash "$PREP" "$@" > "$T/out" 2>&1 || rc=$?
  cp "$LOG" "$T/calls"
}
prep_fresh() { # same, with no Caddy on PATH
  rc=0; : > "$LOG"
  env PATH="$STUB:$CLEAN_PATH" PREP_ROOT="$ROOT" OP_HOST="$OP" ADMIN_HOST="$ADM" MON_HOST="$MON" \
    bash "$PREP" "$@" > "$T/out" 2>&1 || rc=$?
  cp "$LOG" "$T/calls"
}
# The prep decides whether Caddy is installed with `command -v caddy`: keep a real one off PATH.
CLEAN_PATH=""
IFS=:; for d in $PATH; do [ -x "$d/caddy" ] || CLEAN_PATH="$CLEAN_PATH${CLEAN_PATH:+:}$d"; done; unset IFS
MUTATING='^(apt-get|curl|useradd|chown|ufw|systemctl|caddy validate|runuser CREATE)'
get_env() { sed -nE "s/^$2=(.*)$/\1/p" "$1" | tail -1; }   # as socrate-vps-install.sh reads it
mode() { stat -c %a "$1"; }
snap() { (cd "$ROOT" && find . -printf '%p %m %s\n' | LC_ALL=C sort && find . -type f -exec sha256sum {} + | LC_ALL=C sort); }

echo "socrate-vps-prep.sh:"

# 1. --help and argument checks.
rc=0; bash "$PREP" --help > "$T/out" 2>&1 || rc=$?
if [ "$rc" = 0 ] && grep -q -- '--apply' "$T/out" && grep -q -- '--op-host' "$T/out" && grep -q -- '--smtp-password-file' "$T/out"; then
  pass "--help documents the inputs"; else fail "--help: rc=$rc"; show "$T/out"; fi
os_release 24.04 noble
prep --bogus
[ "$rc" != 0 ] && grep -q 'unknown argument' "$T/out" && pass "unknown argument refused" || { fail "unknown argument: rc=$rc"; show "$T/out"; }
prep --op-host 'Bad_Host' --apply
[ "$rc" != 0 ] && grep -q 'not a lower-case DNS name' "$T/out" && pass "invalid host refused" || { fail "invalid host: rc=$rc"; show "$T/out"; }
prep --apply --dry-run
[ "$rc" != 0 ] && pass "--apply with --dry-run refused" || { fail "--apply --dry-run: rc=$rc"; show "$T/out"; }
os_release 20.04 focal
prep
[ "$rc" != 0 ] && grep -q 'supported: Ubuntu 22.04 or 24.04' "$T/out" && pass "Ubuntu 20.04 refused" || { fail "20.04: rc=$rc"; show "$T/out"; }

# 2. Dry run on a fresh 22.04 host: the plan names PostgreSQL 16 from PGDG, Caddy from its repo,
#    SSH before 80/443, and nothing changes.
rm -rf "$ROOT"; os_release 22.04 jammy; touch "$STATE/fresh"
prep_fresh --firewall --acme-email ops@example.test
plan_ok=1
for p in 'add apt source pgdg' 'jammy-pgdg' 'add apt source caddy-stable' 'apt-get install:.* postgresql-16.* caddy' \
         'create system user and group socrate-mon-bff' 'create /etc/socrate/socrate.env \(0640 root:socrate\)' \
         'create Postgres role socrate' 'create /etc/caddy/sites/admin.example.test.caddy' 'ufw allow 2222/tcp'; do
  grep -qE -- "$p" "$T/out" || { plan_ok=0; echo "      missing from the plan: $p"; }
done
first_ufw="$(grep -oE 'ufw allow [0-9]+/tcp' "$T/out" | head -1)"
if [ "$rc" = 0 ] && [ "$plan_ok" = 1 ] && [ "$first_ufw" = "ufw allow 22/tcp" ]; then pass "fresh 22.04 dry run: full plan, SSH allowed first"; else
  fail "fresh dry run: rc=$rc first ufw rule '$first_ufw'"; show "$T/out"; fi
if [ "$(find "$ROOT" -type f | wc -l)" = 1 ] && ! grep -qE "$MUTATING" "$T/calls"; then pass "dry run changes nothing"; else
  fail "dry run changed something"; find "$ROOT" -type f; show "$T/calls"; fi
rm -f "$STATE/fresh"

# 3. --apply on a 24.04 host with PostgreSQL 16 and Caddy installed (the package's default
#    Caddyfile in place), with SMTP and a password holding shell metacharacters.
rm -rf "$ROOT"; os_release 24.04 noble
mkdir -p "$ROOT/etc/caddy"
printf '# The Caddyfile is an easy way to configure your Caddy web server.\n:80 {\n\troot * /usr/share/caddy\n\tfile_server\n}\n' > "$ROOT/etc/caddy/Caddyfile"
SMTP_PW='p@ss w$rd"x`y\z'
printf '%s\n' "$SMTP_PW" > "$T/smtp-pw"
prep --apply --acme-email ops@example.test --smtp-host smtp.example.test --smtp-user mailer \
  --smtp-password-file "$T/smtp-pw" --from-email no-reply@example.test --from-name 'Socrate Test'
E="$ROOT/etc/socrate"
if [ "$rc" = 0 ]; then pass "--apply succeeds"; else fail "--apply: rc=$rc"; show "$T/out"; fi
keys_ok=1
check_key() { # file key expected-value
  [ "$(get_env "$1" "$2")" = "$3" ] || { keys_ok=0; echo "      $(basename "$1"): $2='$(get_env "$1" "$2")', want '$3'"; }
}
check_key "$E/socrate.env" ENV production
check_key "$E/socrate.env" PORT 8080
check_key "$E/socrate.env" ADMIN_PORT 8082
check_key "$E/socrate.env" ADMIN_BIND_HOST 127.0.0.1
check_key "$E/socrate.env" OAUTH_ISSUER "https://$OP"
check_key "$E/socrate.env" KEYS_PATH /var/lib/socrate/keys
check_key "$E/socrate.env" AUTO_MIGRATE false
check_key "$E/socrate.env" ADMIN_PASSWORD_LOGIN_ENABLED false
check_key "$E/socrate.env" SMTP_HOST smtp.example.test
for f in admin-bff bff; do
  check_key "$E/$f.env" BFF_CLIENT_ID "$PLACEHOLDER"
  check_key "$E/$f.env" BFF_CLIENT_SECRET "$PLACEHOLDER"
  check_key "$E/$f.env" BFF_ADMIN_UPSTREAM http://127.0.0.1:8082
  check_key "$E/$f.env" BFF_OAUTH_UPSTREAM http://127.0.0.1:8080
  check_key "$E/$f.env" BFF_OAUTH_PUBLIC_URL "https://$OP"
  check_key "$E/$f.env" BFF_COOKIE_SECURE true
  grep -q '^BFF_SESSION_DSN=' "$E/$f.env" && { keys_ok=0; echo "      $f.env sets BFF_SESSION_DSN"; }
done
check_key "$E/admin-bff.env" BFF_LISTEN_ADDR 127.0.0.1:8092
check_key "$E/admin-bff.env" BFF_PUBLIC_ORIGIN "https://$ADM"
check_key "$E/bff.env" BFF_LISTEN_ADDR 127.0.0.1:8090
check_key "$E/bff.env" BFF_PUBLIC_ORIGIN "https://$MON"
DSN="$(get_env "$E/socrate.env" DATABASE_URL)"; SKB="$(get_env "$E/socrate.env" SECRET_KEY_BASE)"
DB_PW="$(printf '%s' "$DSN" | sed -nE 's#^postgres://socrate:([0-9a-f]{48})@127\.0\.0\.1:5432/socrate\?sslmode=disable$#\1#p')"
[ -n "$DB_PW" ] || { keys_ok=0; echo "      DATABASE_URL has an unexpected form"; }
printf '%s' "$SKB" | grep -qE '^[0-9a-f]{64}$' || { keys_ok=0; echo "      SECRET_KEY_BASE is not 64 hex characters"; }
[ "$keys_ok" = 1 ] && pass "env files carry every key the installer and the services read" || fail "env file keys"

# The installer sources socrate.env in bash (socrate-seed); systemd reads it too.
sourced="$(env -i bash -c 'set -a; . "$1"; set +a; printf "%s|%s|%s" "$DATABASE_URL" "$SMTP_PASSWORD" "$FROM_NAME"' _ "$E/socrate.env" 2>&1)" || true
[ "$sourced" = "$DSN|$SMTP_PW|Socrate Test" ] && pass "socrate.env sources cleanly in bash (SMTP password kept literally)" \
  || { fail "sourcing socrate.env gave '$sourced'"; }
[ -n "$DB_PW" ] && [ "$(cat "$STATE/role-pw" 2>/dev/null)" = "$DB_PW" ] && pass "Postgres role created with socrate.env's password" \
  || fail "role password differs from DATABASE_URL"
grep -q 'runuser CREATE DATABASE' "$T/calls" && pass "database created" || fail "database not created"
if [ -n "$DB_PW" ] && ! grep -qF -- "$DB_PW" "$T/out" && ! grep -qF -- "$SKB" "$T/out" && ! grep -qF -- 'w$rd' "$T/out"; then
  pass "no secret in the output"; else fail "a secret was printed"; fi

modes_ok=1
for spec in etc/socrate/socrate.env:640 etc/socrate/admin-bff.env:640 etc/socrate/bff.env:640 \
            usr/local/sbin/socrate-backup.sh:750 etc/cron.d/socrate-backup:644 etc/caddy/Caddyfile:644 \
            "etc/caddy/sites/$OP.caddy:644" "etc/caddy/sites/$ADM.caddy:644" "etc/caddy/sites/$MON.caddy:644" \
            var/lib/socrate:700 var/lib/socrate/keys:700 var/backups/socrate:700 srv/admin/dist:755 srv/monitoring/dist:755 etc/socrate:755; do
  p="${spec%:*}"; want="${spec##*:}"
  [ -e "$ROOT/$p" ] && [ "$(mode "$ROOT/$p")" = "$want" ] || { modes_ok=0; echo "      /$p: $(mode "$ROOT/$p" 2>/dev/null || echo missing), want $want"; }
done
[ "$modes_ok" = 1 ] && pass "files and directories have the expected modes" || fail "modes"
own_ok=1
for spec in "root:socrate $ROOT/etc/socrate/socrate.env" "root:socrate-admin-bff $ROOT/etc/socrate/admin-bff.env" \
            "root:socrate-mon-bff $ROOT/etc/socrate/bff.env" "socrate:socrate $ROOT/var/lib/socrate/keys"; do
  grep -qF "chown $spec" "$T/calls" || { own_ok=0; echo "      no 'chown $spec'"; }
done
for u in socrate socrate-admin-bff socrate-mon-bff; do grep -qE "^useradd .*--system.* $u\$" "$T/calls" || { own_ok=0; echo "      no useradd $u"; }; done
[ "$own_ok" = 1 ] && pass "service users created; env files owned root:<service group>" || { fail "ownership"; show "$T/calls"; }
if grep -qF 'email ops@example.test' "$ROOT/etc/caddy/Caddyfile" && grep -qxF 'import /etc/caddy/sites/*.caddy' "$ROOT/etc/caddy/Caddyfile" \
  && ls "$ROOT"/var/backups/socrate/caddy-prep-*/Caddyfile >/dev/null 2>&1 && grep -q 'caddy validate' "$T/calls" \
  && grep -q 'systemctl reload-or-restart caddy' "$T/calls"; then
  pass "package Caddyfile replaced (copy kept), validated, Caddy reloaded"
else fail "main Caddyfile"; show "$ROOT/etc/caddy/Caddyfile"; show "$T/calls"; fi
# Optional: CADDY_BIN=/path/to/caddy also validates the configuration with a real Caddy.
if [ -n "${CADDY_BIN:-}" ]; then
  mkdir -p "$T/validate"
  sed "s#^import /etc/caddy/sites/#import $ROOT/etc/caddy/sites/#" "$ROOT/etc/caddy/Caddyfile" > "$T/validate/Caddyfile"
  rc=0; HOME="$T/validate" XDG_DATA_HOME="$T/validate" XDG_CONFIG_HOME="$T/validate" \
    "$CADDY_BIN" validate --config "$T/validate/Caddyfile" --adapter caddyfile > "$T/out" 2>&1 || rc=$?
  if [ "$rc" = 0 ] && ! grep -qi 'not formatted' "$T/out"; then pass "real caddy validates the prepared configuration"; else
    fail "caddy validate: rc=$rc"; show "$T/out"; fi
fi
if grep -qE '^[[:space:]]*reverse_proxy @bff' "$ROOT/etc/caddy/sites/$MON.caddy"; then
  fail "monitor site has the bare 'reverse_proxy @bff' the installer repairs"; else pass "monitor site routes @bff through handle"; fi

# 4. A second --apply changes nothing.
before="$(snap)"
prep --apply --acme-email ops@example.test
if [ "$rc" = 0 ] && [ "$before" = "$(snap)" ] && ! grep -qE "$MUTATING" "$T/calls" && grep -q 'kept     /etc/socrate/socrate.env' "$T/out"; then
  pass "second --apply: nothing changed, everything reported kept"
else
  fail "second --apply: rc=$rc"; show "$T/out"; show "$T/calls"; diff <(echo "$before") <(snap) | head -20
fi

# 5. socrate-caddy-update.sh accepts the sites: a bundle carrying the values socrate-release.sh
#    would extract from them gives "Nothing to do."; a newer bundle is planned and applied.
SITES="$ROOT/etc/caddy/sites"; A="$SITES/$ADM.caddy"
mkdir -p "$T/bundle/caddy" "$T/ustub"
for c in caddy systemctl; do printf '#!/bin/sh\nexit 0\n' > "$T/ustub/$c"; chmod +x "$T/ustub/$c"; done
printf '#!/bin/sh\nexit 7\n' > "$T/ustub/curl"; chmod +x "$T/ustub/curl"
# The same expressions socrate-release.sh applies to oauth2-admin's deploy/Caddyfile.
sed -nE 's/^[[:space:]]*Content-Security-Policy[[:space:]]+"([^"]*)".*/\1/p' "$A" > "$T/bundle/caddy/admin-csp.txt"
sed -nE 's/^[[:space:]]*Content-Security-Policy-Report-Only[[:space:]]+"([^"]*)".*/\1/p' "$A" > "$T/bundle/caddy/admin-csp-report-only.txt"
sed -nE 's/^[[:space:]]*Reporting-Endpoints[[:space:]]+`([^`]*)`.*/\1/p' "$A" > "$T/bundle/caddy/admin-reporting-endpoints.txt"
sed -nE 's/^[[:space:]]*@bff[[:space:]]+path[[:space:]]+(.*)$/\1/p' "$A" > "$T/bundle/caddy/admin-bff-paths.txt"
for f in admin-csp admin-csp-report-only admin-reporting-endpoints admin-bff-paths; do
  [ "$(grep -c . "$T/bundle/caddy/$f.txt")" = 1 ] || fail "socrate-release.sh's extraction of $f from the admin site: $(cat "$T/bundle/caddy/$f.txt")"
done
update() { # [--apply]
  rc=0
  $SUDO env PATH="$T/ustub:$PATH" SITES="$SITES" ADMIN_HOST="$ADM" MON_HOST="$MON" \
    CADDYFILE="$ROOT/etc/caddy/Caddyfile" BACKUP_ROOT="$T/backups" \
    bash "$KIT_DIR/socrate-caddy-update.sh" "$T/bundle" "$@" > "$T/out" 2>&1 || rc=$?
}
update
if [ "$rc" = 0 ] && grep -q 'Nothing to do' "$T/out"; then pass "caddy updater: prepared sites need nothing"; else
  fail "caddy updater on prepared sites: rc=$rc"; show "$T/out"; fi
sed 's/; object-src/; worker-src '"'"'none'"'"'; object-src/' "$T/bundle/caddy/admin-csp.txt" > "$T/csp" && mv "$T/csp" "$T/bundle/caddy/admin-csp.txt"
printf '%s /api/new/*\n' "$(cat "$T/bundle/caddy/admin-bff-paths.txt")" > "$T/paths" && mv "$T/paths" "$T/bundle/caddy/admin-bff-paths.txt"
update
if [ "$rc" = 0 ] && grep -qF 'admin @bff matcher: adding /api/new/*' "$T/out" && grep -q 'Dry run only' "$T/out"; then
  pass "caddy updater: a newer bundle's CSP and path are planned"; else fail "newer bundle plan: rc=$rc"; show "$T/out"; fi
update --apply
if [ "$rc" = 0 ] && grep -qF "worker-src 'none'" "$A" && grep -qE '^[[:space:]]*@bff path .* /api/new/\*$' "$A"; then
  update
  if [ "$rc" = 0 ] && grep -q 'Nothing to do' "$T/out"; then pass "caddy updater: --apply brings the site in line"; else
    fail "after --apply: rc=$rc"; show "$T/out"; fi
else fail "updater --apply: rc=$rc"; show "$T/out"; show "$A"; fi

# 6. The backup script prints the line the runbook reads, keeps KEEP dumps, and writes 0600.
BK="$T/bk"; mkdir -p "$BK"
for d in 20200101-000000 20200102-000000 20200103-000000; do echo old > "$BK/socrate-$d.sql.gz"; touch -d "${d%%-*}" "$BK/socrate-$d.sql.gz"; done
rc=0
$SUDO env PATH="$STUB:$PATH" OUT_DIR="$BK" KEEP=2 bash "$ROOT/usr/local/sbin/socrate-backup.sh" > "$T/out" 2>&1 || rc=$?
last="$(tail -1 "$T/out")"
newest="$($SUDO sh -c 'ls -1t "$1"/socrate-*.sql.gz | head -1' sh "$BK")"
if [ "$rc" = 0 ] && printf '%s\n' "$last" | grep -qE "^done: OK $BK/socrate-[0-9]{8}-[0-9]{6}\.sql\.gz [^ ]+ migrations=31\$" \
  && [ "$($SUDO sh -c 'ls -1 "$1"/socrate-*.sql.gz | wc -l' sh "$BK")" = 2 ] && [ "$($SUDO stat -c %a "$newest")" = 600 ] \
  && grep -q 'exclude-table-data=bff_store_sessions' "$LOG"; then
  pass "backup script: '$last'"
else fail "backup script: rc=$rc"; show "$T/out"; $SUDO ls -l "$BK"; fi

# 7. A Postgres role without the env file holding its password stops the run before any change.
rm -rf "$ROOT"; os_release 24.04 noble; touch "$STATE/role"
prep --apply
if [ "$rc" != 0 ] && grep -q "role 'socrate' exists but /etc/socrate/socrate.env does not" "$T/out" \
  && [ "$(find "$ROOT" -type f | wc -l)" = 1 ] && ! grep -qE "$MUTATING" "$T/calls"; then
  pass "orphan role refused before any change"; else fail "orphan role: rc=$rc"; show "$T/out"; fi

[ "$fails" = 0 ] || { echo "$fails failure(s)"; exit 1; }
echo "all passed"
