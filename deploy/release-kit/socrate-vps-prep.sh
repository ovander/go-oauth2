#!/usr/bin/env bash
# socrate-vps-prep.sh - prepare a fresh Ubuntu VPS, once, for the Socrate suite release kit.
# Run as root on the VPS, before the first socrate-vps-install.sh:
#
#   sudo bash socrate-vps-prep.sh --acme-email ops@example.com            # dry run: show the plan
#   sudo bash socrate-vps-prep.sh --acme-email ops@example.com --apply    # do it
#
# It installs PostgreSQL 16 and Caddy, creates the service users, directories, the Postgres
# role and database, the three env files (secrets generated here, never printed), the backup
# script the runbook calls, and the Caddy sites in the form socrate-caddy-update.sh edits.
# The systemd units, binaries and SPAs come from the release bundle (socrate-vps-install.sh);
# the console OAuth clients are registered by that installer on its first run.
#
# Idempotent: anything already there (env file, secret, role, database, Caddy site) is kept and
# reported, never overwritten. See --help for the inputs.
#
# ASCII only. PREP_ROOT (tests only) prefixes every file path this script reads or writes;
# the system commands are then expected to be stubs on PATH, and root is not required.
set -euo pipefail

usage() {
  cat <<'EOF'
usage: sudo bash socrate-vps-prep.sh [options] [--apply]

Prepares a fresh Ubuntu 22.04 / 24.04 VPS for socrate-vps-install.sh. Without --apply it only
prints the plan (the default, also --dry-run); with --apply it makes the changes. Safe to re-run.

Host names (the same variables socrate-vps-install.sh and socrate-caddy-update.sh read; give
them the same values there when they are not the defaults):
  --op-host HOST        issuer host           OP_HOST     (default socrate.vandermoten.eu)
  --admin-host HOST     admin console host    ADMIN_HOST  (default admin.socrate.vandermoten.eu)
  --mon-host HOST       monitoring console    MON_HOST    (default monitor.socrate.vandermoten.eu)

Caddy:
  --acme-email EMAIL    ACME account e-mail (expiry notices)   ACME_EMAIL   (optional)

Mail, written into socrate.env only when this run creates it (all optional):
  --smtp-host HOST      SMTP_HOST
  --smtp-port PORT      SMTP_PORT       (default 587)
  --smtp-security MODE  SMTP_SECURITY   starttls | ssl | tls | none (default starttls)
  --smtp-user USER      SMTP_USERNAME
  --smtp-password-file FILE
                        file whose first line is the SMTP password   SMTP_PASSWORD_FILE
                        (or export SMTP_PASSWORD; never put a secret on the command line)
  --from-email EMAIL    FROM_EMAIL
  --from-name NAME      FROM_NAME       (default Socrate; letters, digits, space . _ -)

Firewall (opt-in):
  --firewall            ufw: allow SSH (22 and sshd's own port) first, then 80 and 443, deny
                        other inbound, enable. Existing rules are kept.  FIREWALL=1

  --apply               make the changes
  --dry-run             print the plan only (the default)
  -h, --help            this help

Fixed by the kit (socrate-vps-install.sh expects them): ports 8080 (OP), 8082 (admin API,
loopback), 8090 (monitoring BFF), 8092 (admin BFF); users socrate, socrate-admin-bff,
socrate-mon-bff; database and role socrate; /etc/socrate/{socrate,admin-bff,bff}.env;
/var/lib/socrate/keys; /srv/{admin,monitoring}/dist; /var/backups/socrate;
/etc/caddy/sites/<host>.caddy; /usr/local/sbin/socrate-backup.sh.

Then: upload the bundle, run socrate-vps-install.sh (registers the first superadmin and the
two console clients), then socrate-caddy-update.sh (dry run, then --apply).
EOF
}

ok()   { printf '  [ok] %s\n' "$*"; }
info() { printf '  - %s\n' "$*"; }
warn() { printf '  [warn] %s\n' "$*"; WARNINGS=$((WARNINGS + 1)); }
plan() { printf '  [plan] %s\n' "$*"; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
step() { printf '\n==> %s\n' "$*"; }
WARNINGS=0

# ---- inputs ---------------------------------------------------------------------------
APPLY=0; SEEN_DRY=0
FIREWALL="${FIREWALL:-0}"
OP_HOST="${OP_HOST:-socrate.vandermoten.eu}"
ADMIN_HOST="${ADMIN_HOST:-admin.socrate.vandermoten.eu}"
MON_HOST="${MON_HOST:-monitor.socrate.vandermoten.eu}"
ACME_EMAIL="${ACME_EMAIL:-}"
SMTP_HOST="${SMTP_HOST:-}"; SMTP_PORT="${SMTP_PORT:-587}"; SMTP_SECURITY="${SMTP_SECURITY:-starttls}"
SMTP_USERNAME="${SMTP_USERNAME:-}"; SMTP_PASSWORD_FILE="${SMTP_PASSWORD_FILE:-}"
FROM_EMAIL="${FROM_EMAIL:-}"; FROM_NAME="${FROM_NAME:-Socrate}"

while [ $# -gt 0 ]; do
  case "$1" in
    --apply) APPLY=1;;
    --dry-run) SEEN_DRY=1;;
    --firewall) FIREWALL=1;;
    -h|--help) usage; exit 0;;
    --op-host|--admin-host|--mon-host|--acme-email|--smtp-host|--smtp-port|--smtp-security|--smtp-user|--smtp-password-file|--from-email|--from-name)
      [ $# -ge 2 ] || die "$1 needs a value (see --help)"
      case "$1" in
        --op-host) OP_HOST="$2";; --admin-host) ADMIN_HOST="$2";; --mon-host) MON_HOST="$2";;
        --acme-email) ACME_EMAIL="$2";; --smtp-host) SMTP_HOST="$2";; --smtp-port) SMTP_PORT="$2";;
        --smtp-security) SMTP_SECURITY="$2";; --smtp-user) SMTP_USERNAME="$2";;
        --smtp-password-file) SMTP_PASSWORD_FILE="$2";; --from-email) FROM_EMAIL="$2";;
        --from-name) FROM_NAME="$2";;
      esac
      shift;;
    *) die "unknown argument: $1 (see --help)";;
  esac
  shift
done
[ "$APPLY" = 1 ] && [ "$SEEN_DRY" = 1 ] && die "--apply and --dry-run together: choose one"

R="${PREP_ROOT:-}"
OP_PORT=8080 ADMIN_API_PORT=8082 MON_BFF_PORT=8090 ADMIN_BFF_PORT=8092
DB_NAME=socrate DB_ROLE=socrate
ENV_OP=/etc/socrate/socrate.env
ENV_ADMIN=/etc/socrate/admin-bff.env
ENV_MON=/etc/socrate/bff.env
SITES=/etc/caddy/sites
CADDYFILE=/etc/caddy/Caddyfile
BACKUP_SCRIPT=/usr/local/sbin/socrate-backup.sh
BACKUP_CRON=/etc/cron.d/socrate-backup
PLACEHOLDER=CHANGE_ME_AFTER_CLIENT_REGISTRATION   # socrate-vps-install.sh registers the client while it sees this
MARK="written by socrate-vps-prep.sh"
STAMP="$(date +%Y%m%d-%H%M%S)"
SUMMARY=""
note() { SUMMARY="$SUMMARY
  $1"; }   # one summary line: "<created|kept|...>  <what>"

valid_host() {
  case "$1" in ""|*[!a-z0-9.-]*|.*|*.|*..*|-*) return 1;; *.*) return 0;; *) return 1;; esac
}
valid_email() {
  case "$1" in *[!A-Za-z0-9.@_+-]*|*@*@*|@*|*@) return 1;; *@*.*) return 0;; *) return 1;; esac
}

# ---- 0. preflight ---------------------------------------------------------------------
step "0/9 preflight"
[ -n "$R" ] || [ "$(id -u)" = 0 ] || die "run as root: sudo bash $0 (see --help)"
for h in "$OP_HOST" "$ADMIN_HOST" "$MON_HOST"; do valid_host "$h" || die "not a lower-case DNS name: '$h'"; done
[ "$OP_HOST" != "$ADMIN_HOST" ] && [ "$OP_HOST" != "$MON_HOST" ] && [ "$ADMIN_HOST" != "$MON_HOST" ] \
  || die "the issuer, admin and monitoring hosts must differ"
[ -z "$ACME_EMAIL" ] || valid_email "$ACME_EMAIL" || die "--acme-email: not an e-mail address: '$ACME_EMAIL'"
[ -z "$FROM_EMAIL" ] || valid_email "$FROM_EMAIL" || die "--from-email: not an e-mail address: '$FROM_EMAIL'"
[ -z "$SMTP_HOST" ] || valid_host "$SMTP_HOST" || die "--smtp-host: not a lower-case DNS name: '$SMTP_HOST'"
case "$SMTP_PORT" in ''|*[!0-9]*) die "--smtp-port: not a number: '$SMTP_PORT'";; esac
case "$SMTP_SECURITY" in starttls|ssl|tls|none) ;; *) die "--smtp-security: starttls, ssl, tls or none";; esac
case "$SMTP_USERNAME" in *[!A-Za-z0-9.@_+=-]*) die "--smtp-user: unexpected character in '$SMTP_USERNAME'";; esac
case "$FROM_NAME" in ''|*[!A-Za-z0-9\ ._-]*) die "--from-name: letters, digits, space . _ - only";; esac
SMTP_PW="${SMTP_PASSWORD:-}"
if [ -n "$SMTP_PASSWORD_FILE" ]; then
  [ -r "$SMTP_PASSWORD_FILE" ] || die "--smtp-password-file: cannot read $SMTP_PASSWORD_FILE"
  SMTP_PW="$(head -n 1 "$SMTP_PASSWORD_FILE" | tr -d '\r')"
fi
# Written single-quoted, which both systemd and the installer's `. socrate.env` read literally.
case "$SMTP_PW" in *"'"*) die "the SMTP password contains a single quote, which the env file cannot hold";; esac

OS_RELEASE="$R/etc/os-release"
[ -r "$OS_RELEASE" ] || die "$OS_RELEASE not found: not an Ubuntu host?"
OS_ID="$(sed -nE 's/^ID="?([^"]*)"?$/\1/p' "$OS_RELEASE")"
OS_VER="$(sed -nE 's/^VERSION_ID="?([^"]*)"?$/\1/p' "$OS_RELEASE")"
OS_CODENAME="$(sed -nE 's/^VERSION_CODENAME="?([^"]*)"?$/\1/p' "$OS_RELEASE")"
case "$OS_ID $OS_VER" in "ubuntu 22.04"|"ubuntu 24.04") ;; *) die "supported: Ubuntu 22.04 or 24.04 (this is '$OS_ID $OS_VER')";; esac
ok "Ubuntu $OS_VER ($OS_CODENAME)"
if [ "$APPLY" = 1 ]; then info "mode: APPLY"; else info "mode: dry run (nothing is changed; re-run with --apply)"; fi
info "issuer https://$OP_HOST   admin https://$ADMIN_HOST   monitoring https://$MON_HOST"
info "ports: OP $OP_PORT, admin API $ADMIN_API_PORT (loopback), monitoring BFF $MON_BFF_PORT, admin BFF $ADMIN_BFF_PORT"
info "ACME e-mail: ${ACME_EMAIL:-<none>}   SMTP: ${SMTP_HOST:-<none>}   firewall: $([ "$FIREWALL" = 1 ] && echo 'ufw (22, 80, 443)' || echo 'not changed')"
[ -n "$ACME_EMAIL" ] || warn "no --acme-email: Caddy still gets certificates, but nobody is told when renewal fails"

pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'; }
# pg_q SQL [DB]: one query as the postgres superuser, unaligned, no header; empty on no row.
pg_q() { local sql="$1"; shift; runuser -u postgres -- psql -X -q -t -A -v ON_ERROR_STOP=1 -c "$sql" "$@"; }
# pg_exec: SQL on stdin (so a password never appears in a process list).
pg_exec() { runuser -u postgres -- psql -X -q -v ON_ERROR_STOP=1 >/dev/null; }

# PostgreSQL: only 16 is supported, on the default cluster port 5432.
pg_cluster_state() { # sets PG_STATE to "ok" (16 on 5432) or "none", and PG_STATUS; dies on any other layout
  PG_STATE=none; PG_STATUS=""
  command -v pg_lsclusters >/dev/null 2>&1 || return 0
  local ver name port status rest
  while read -r ver name port status rest; do
    [ -n "$ver" ] || continue
    if [ "$port" = 5432 ] && [ "$ver" != 16 ]; then die "PostgreSQL $ver ($name) holds port 5432: only PostgreSQL 16 is supported"; fi
    if [ "$ver" = 16 ] && [ "$port" = 5432 ]; then PG_STATE=ok; PG_STATUS="$status"; fi
    if [ "$ver" = 16 ] && [ "$port" != 5432 ]; then die "PostgreSQL 16 cluster '$name' listens on $port, not 5432"; fi
  done < <(pg_lsclusters -h 2>/dev/null)
}
pg_cluster_state
if [ "$PG_STATE" = none ] && pkg_installed postgresql-16; then
  die "postgresql-16 is installed but has no cluster on 5432: create it (pg_createcluster 16 main --start) and re-run"
fi

# A role without the env file that holds its password cannot be reconciled without changing a
# secret: stop before touching anything.
ROLE_EXISTS=0; DB_EXISTS=0
if [ "$PG_STATE" = ok ] && [ "${PG_STATUS:-online}" = online ]; then
  [ "$(pg_q "SELECT 1 FROM pg_roles WHERE rolname='$DB_ROLE'")" = 1 ] && ROLE_EXISTS=1
  [ "$(pg_q "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'")" = 1 ] && DB_EXISTS=1
  if [ "$ROLE_EXISTS" = 1 ] && [ ! -e "$R$ENV_OP" ]; then
    die "Postgres role '$DB_ROLE' exists but $ENV_OP does not: restore socrate.env from a backup (its DATABASE_URL holds the role's password), or set a new password on the role and write socrate.env by hand. Nothing was changed."
  fi
fi
ok "preflight passed"

# ---- 1. packages ----------------------------------------------------------------------
step "1/9 packages"
PKGS=""
for p in ca-certificates curl openssl python3 sudo iproute2 rsync gzip cron; do
  pkg_installed "$p" || PKGS="$PKGS $p"
done
[ "$FIREWALL" = 1 ] && ! pkg_installed ufw && PKGS="$PKGS ufw"
NEW_REPO=0
KEYRINGS=/etc/apt/keyrings
add_repo() { # name key-url list-line
  local key="$KEYRINGS/$1.asc" list="/etc/apt/sources.list.d/$1.list"
  if [ -f "$R$list" ] && [ -s "$R$key" ]; then info "apt source $1: kept"; return; fi
  if [ "$APPLY" = 1 ]; then
    install -d -m 0755 "$R$KEYRINGS"
    curl -fsSL --retry 3 "$2" -o "$R$key.tmp" || die "downloading the $1 signing key failed ($2)"
    grep -q 'BEGIN PGP PUBLIC KEY BLOCK' "$R$key.tmp" || die "$2 is not an armored PGP key"
    chmod 0644 "$R$key.tmp"; mv "$R$key.tmp" "$R$key"
    printf '%s\n' "$3" > "$R$list"; chmod 0644 "$R$list"
    ok "apt source $1 added ($list)"
  else
    plan "add apt source $1: $list ($3), key $key from $2"
  fi
  NEW_REPO=1; note "created  apt source $1"
}
if [ "$PG_STATE" = ok ]; then
  ok "PostgreSQL 16 on 5432 (${PG_STATUS:-online})"
else
  PKGS="$PKGS postgresql-16"
  # 24.04 ships 16 in main; 22.04 ships 14, so 16 comes from the PostgreSQL project's repository.
  if [ "$OS_VER" = 22.04 ]; then
    add_repo pgdg https://www.postgresql.org/media/keys/ACCC4CF8.asc \
      "deb [signed-by=$KEYRINGS/pgdg.asc] https://apt.postgresql.org/pub/repos/apt $OS_CODENAME-pgdg main"
  fi
fi
if command -v caddy >/dev/null 2>&1; then
  ok "Caddy present ($(caddy version 2>/dev/null | cut -d' ' -f1))"
else
  PKGS="$PKGS caddy"
  add_repo caddy-stable https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
    "deb [signed-by=$KEYRINGS/caddy-stable.asc] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main"
fi
if [ -n "$PKGS" ]; then
  if [ "$APPLY" = 1 ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q >/dev/null || die "apt-get update failed"
    # shellcheck disable=SC2086 # one word per package
    apt-get install -y -q --no-install-recommends $PKGS >/dev/null || die "apt-get install failed:$PKGS"
    ok "installed:$PKGS"
  else
    [ "$NEW_REPO" = 1 ] && plan "apt-get update"
    plan "apt-get install:$PKGS"
  fi
  note "created  packages:$PKGS"
else
  ok "required packages present"
fi
if [ "$APPLY" = 1 ] && [ "$PG_STATE" != ok ]; then
  pg_cluster_state
  [ "$PG_STATE" = ok ] || die "PostgreSQL 16 installed but no cluster answers on 5432 (pg_lsclusters)"
  ok "PostgreSQL 16 cluster on 5432"
fi
if [ "$APPLY" = 1 ]; then
  systemctl is-enabled --quiet postgresql 2>/dev/null || systemctl enable --quiet postgresql
  systemctl is-active --quiet postgresql || systemctl start postgresql
  [ "$(pg_q 'SHOW server_version_num' | cut -c1-2)" = 16 ] || die "the server on 5432 is not PostgreSQL 16"
fi

# ---- 2. firewall ----------------------------------------------------------------------
step "2/9 firewall"
if [ "$FIREWALL" = 1 ]; then
  ssh_ports="22 $(sshd -T 2>/dev/null | awk '$1 == "port" {print $2}' | tr '\n' ' ')"
  ufw_status="$(ufw status 2>/dev/null || true)"
  # SSH first, so enabling ufw can never cut the session that runs this script.
  for p in $(echo "$ssh_ports 80 443" | tr ' ' '\n' | awk 'NF && !seen[$0]++'); do
    if printf '%s\n' "$ufw_status" | grep -qE "^$p/tcp +ALLOW"; then info "ufw allows $p/tcp: kept"; continue; fi
    if [ "$APPLY" = 1 ]; then ufw allow "$p/tcp" >/dev/null; ok "ufw allow $p/tcp"; else plan "ufw allow $p/tcp"; fi
    note "created  ufw rule $p/tcp"
  done
  if printf '%s\n' "$ufw_status" | grep -q '^Status: active'; then
    ok "ufw already active (other rules kept)"
  elif [ "$APPLY" = 1 ]; then
    ufw default deny incoming >/dev/null && ufw default allow outgoing >/dev/null && ufw --force enable >/dev/null
    ok "ufw enabled: inbound denied except the rules above"; note "created  ufw enabled"
  else
    plan "ufw default deny incoming; ufw --force enable"
  fi
else
  st="$(ufw status 2>/dev/null | head -1)" || true
  info "not changed (${st:-ufw not installed}); --firewall allows 22, 80 and 443 and enables ufw"
fi

# ---- 3. users -------------------------------------------------------------------------
step "3/9 service users"
# One no-login user per service: the identity server owns the signing keys and its env; each
# BFF reads only its own env file (the units name these users).
for u in socrate socrate-admin-bff socrate-mon-bff; do
  if getent passwd "$u" >/dev/null 2>&1; then info "user $u: kept"; note "kept     user $u"; continue; fi
  if [ "$APPLY" = 1 ]; then
    useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "$u"; ok "user $u created"
  else
    plan "create system user and group $u (no login)"
  fi
  note "created  user $u"
done

# ---- 4. directories -------------------------------------------------------------------
step "4/9 directories"
ensure_dir() { # path mode owner:group - an existing directory is kept as it is
  local d="$1" mode="$2" owner="$3" have
  if [ -d "$R$d" ]; then
    have="$(stat -c %a "$R$d")"
    if [ "$have" = "${mode#0}" ]; then info "$d: kept"; else warn "$d: kept with mode $have (a new one gets $mode)"; fi
    return
  fi
  if [ "$APPLY" = 1 ]; then
    install -d -m "$mode" "$R$d"; chown "$owner" "$R$d"; ok "$d ($mode $owner)"
  else
    plan "create $d ($mode $owner)"
  fi
  note "created  $d"
}
ensure_dir /etc/socrate 0755 root:root
ensure_dir /var/lib/socrate 0700 socrate:socrate          # the unit's WorkingDirectory
ensure_dir /var/lib/socrate/keys 0700 socrate:socrate     # KEYS_PATH: the server creates and rotates its keys here
ensure_dir /var/lib/socrate/data 0750 socrate:socrate     # optional GeoIP databases
ensure_dir /srv/admin 0755 root:root
ensure_dir /srv/admin/dist 0755 root:root                 # SPAs: root-owned, read-only for every service
ensure_dir /srv/monitoring 0755 root:root
ensure_dir /srv/monitoring/dist 0755 root:root
ensure_dir /var/backups/socrate 0700 root:root            # dumps, install-* and caddy-* backups
ensure_dir /etc/caddy 0755 root:root
ensure_dir "$SITES" 0755 root:root
ensure_dir /usr/local/sbin 0755 root:root
ensure_dir /etc/cron.d 0755 root:root

# ---- 5. env files ---------------------------------------------------------------------
step "5/9 env files"
# write_new PATH MODE OWNER:GROUP CONTENT - creates PATH (returns 0), or keeps an existing one
# untouched (returns 1). The content is never printed.
write_new() {
  local f="$1" mode="$2" owner="$3"
  if [ -e "$R$f" ]; then info "$f: kept"; note "kept     $f"; return 1; fi
  if [ "$APPLY" = 1 ]; then
    # Explicit checks: callers use `write_new ... || true`, where set -e does not apply.
    (umask 077; printf '%s\n' "$4" > "$R$f.prep-tmp") || die "cannot write $f"
    { chmod "$mode" "$R$f.prep-tmp" && chown "$owner" "$R$f.prep-tmp" && mv "$R$f.prep-tmp" "$R$f"; } \
      || { rm -f "$R$f.prep-tmp"; die "cannot install $f"; }
    ok "$f ($mode $owner)"
  else
    plan "create $f ($mode $owner)"
  fi
  note "created  $f"
}
# An env file kept from an earlier run keeps its contents; only its mode and group are checked,
# and set as socrate-vps-install.sh sets them at lock-down.
env_perms() { # path group
  [ -e "$R$1" ] || return 0
  local have want="640 $2" fmt='%a %G'
  getent group "$2" >/dev/null 2>&1 || { fmt='%a'; want=640; }   # group not created yet (dry run)
  have="$(stat -c "$fmt" "$R$1")"
  [ "$have" = "$want" ] && return 0
  if [ "$APPLY" = 1 ]; then chown "root:$2" "$R$1"; chmod 0640 "$R$1"; ok "$1: mode 0640 root:$2 (was $have)"
  else plan "$1: set mode 0640 root:$2 (is $have)"; fi
}
secret() { if [ "$APPLY" = 1 ]; then openssl rand -hex "$1"; else echo "<generated>"; fi; }

ENV_OP_CREATED=0
if [ ! -e "$R$ENV_OP" ]; then
  DB_PW="$(secret 24)"; SKB="$(secret 32)"
  if [ -n "$SMTP_HOST" ]; then
    mail="SMTP_HOST=$SMTP_HOST
SMTP_PORT=$SMTP_PORT
SMTP_SECURITY=$SMTP_SECURITY
SMTP_USERNAME=$SMTP_USERNAME
SMTP_PASSWORD='$SMTP_PW'
FROM_EMAIL=${FROM_EMAIL:-no-reply@$OP_HOST}
FROM_NAME=\"$FROM_NAME\""
  else
    mail="# SMTP_HOST=smtp.example.com
# SMTP_PORT=587
# SMTP_SECURITY=starttls
# SMTP_USERNAME=
# SMTP_PASSWORD=
# FROM_EMAIL=no-reply@$OP_HOST
# FROM_NAME=Socrate"
  fi
  op_env() {
  cat <<EOF
# $ENV_OP - Socrate server ($MARK, $STAMP).
# 0640 root:socrate. The secrets below were generated on this host and exist only here.
# socrate-vps-install.sh switches AUTO_MIGRATE and ADMIN_PASSWORD_LOGIN_ENABLED on for its
# first run and back off. Every other variable: go-oauth2's .env.example.
ENV=production

# Public OAuth on $OP_PORT (behind Caddy); the admin API on $ADMIN_API_PORT, loopback only
# (8081 stays free for a legacy server on the same host, see deploy/migration/README.md).
PORT=$OP_PORT
ADMIN_PORT=$ADMIN_API_PORT
ADMIN_BIND_HOST=127.0.0.1

OAUTH_ISSUER=https://$OP_HOST
DATABASE_URL=postgres://$DB_ROLE:$DB_PW@127.0.0.1:5432/$DB_NAME?sslmode=disable
SECRET_KEY_BASE=$SKB

# RSA signing keys: created by the server at its first start and rotated at runtime; the
# unit makes only this directory writable.
KEYS_PATH=/var/lib/socrate/keys

# Caddy and the BFFs connect from loopback.
TRUSTED_PROXIES=127.0.0.1/32,::1/128

# The consoles are same-origin through their BFFs and need no CORS entry. List an
# application origin only if its SPA calls Socrate from the browser.
# ALLOWED_ORIGINS=

AUTO_MIGRATE=false
ADMIN_PASSWORD_LOGIN_ENABLED=false
ADMIN_ELEVATION_MAX_AGE=300

# Mail: invitations, e-mail verification and password reset.
$mail

# Optional GeoIP (MaxMind .mmdb files, readable by the socrate user).
# GEOIP_CITY_DB=/var/lib/socrate/data/GeoLite2-City.mmdb
# GEOIP_ASN_DB=/var/lib/socrate/data/GeoLite2-ASN.mmdb

# Once socrate-vps-install.sh has registered the consoles: their client_ids (BFF_CLIENT_ID in
# admin-bff.env and bff.env), needed before ADMIN_APP_SIGNIN_POLICY or ADMIN_API_AUDIENCE_MODE
# is set to enforce. Every opt-in control stays at its default (off) until you turn it on.
# OPERATOR_CONSOLE_CLIENT_IDS=
EOF
  }
  write_new "$ENV_OP" 0640 root:socrate "$(op_env)" && ENV_OP_CREATED=1
  unset DB_PW SKB mail
else
  write_new "$ENV_OP" 0640 root:socrate "" || true
fi
env_perms "$ENV_OP" socrate

bff_env() { # path group listen-port public-host title
  cat <<EOF
# $1 - $5 ($MARK, $STAMP).
# 0640 root:$2: readable by root and this BFF's own user only.
# The two placeholders are replaced by socrate-vps-install.sh on its first run, when it
# registers this console as a confidential client in Socrate; the secret then lives only here.
BFF_LISTEN_ADDR=127.0.0.1:$3
BFF_ADMIN_UPSTREAM=http://127.0.0.1:$ADMIN_API_PORT
BFF_CLIENT_ID=$PLACEHOLDER
BFF_CLIENT_SECRET=$PLACEHOLDER
BFF_OAUTH_UPSTREAM=http://127.0.0.1:$OP_PORT
BFF_OAUTH_PUBLIC_URL=https://$OP_HOST
BFF_PUBLIC_ORIGIN=https://$4
BFF_SCOPES=openid profile email
BFF_SESSION_IDLE=30m
BFF_SESSION_ABSOLUTE=8h
# Must stay true on an https origin (the BFF refuses false there).
BFF_COOKIE_SECURE=true
EOF
}
admin_env() {
  bff_env "$ENV_ADMIN" socrate-admin-bff "$ADMIN_BFF_PORT" "$ADMIN_HOST" "Socrate Admin BFF"
  cat <<'EOF'
# Per-IP budgets per minute (the defaults).
BFF_LOGIN_RATE=10
BFF_ELEVATE_RATE=5
BFF_PASSWORD_RESET_RATE=5
BFF_CSP_REPORT_RATE=30
EOF
}
write_new "$ENV_ADMIN" 0640 root:socrate-admin-bff "$(admin_env)" || true
env_perms "$ENV_ADMIN" socrate-admin-bff
mon_env() {
  bff_env "$ENV_MON" socrate-mon-bff "$MON_BFF_PORT" "$MON_HOST" "Socrate Monitor BFF"
  cat <<'EOF'
# Sessions are kept in memory. For the durable Postgres store, give the BFF its own role and
# database (never Socrate's), create its tables (oauth2-monitoring deploy/sql/), then set:
# BFF_SESSION_DSN=postgres://socrate_bff:<password>@127.0.0.1:5432/socrate_bff?sslmode=disable
# BFF_SESSION_KEY=<openssl rand -base64 32>
EOF
}
write_new "$ENV_MON" 0640 root:socrate-mon-bff "$(mon_env)" || true
env_perms "$ENV_MON" socrate-mon-bff

# ---- 6. database ----------------------------------------------------------------------
step "6/9 database"
if [ "$APPLY" = 1 ]; then
  # The role's password is the one in socrate.env's DATABASE_URL, whether this run wrote it or
  # an earlier one did: the env file is written first, so a run stopped half-way resumes here.
  dsn_pw="$(sed -nE "s#^DATABASE_URL=postgres(ql)?://$DB_ROLE:([^@]*)@127\.0\.0\.1:5432/$DB_NAME(\?.*)?\$#\2#p" "$R$ENV_OP" | tail -1)"
  ROLE_EXISTS=0; DB_EXISTS=0
  [ "$(pg_q "SELECT 1 FROM pg_roles WHERE rolname='$DB_ROLE'")" = 1 ] && ROLE_EXISTS=1
  [ "$(pg_q "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'")" = 1 ] && DB_EXISTS=1
  if [ "$ROLE_EXISTS" = 1 ] && [ "$ENV_OP_CREATED" = 1 ]; then
    die "role $DB_ROLE already exists, so the password this run wrote into $ENV_OP is not its password: set it on the role by hand (ALTER ROLE $DB_ROLE PASSWORD ..., from DATABASE_URL) and re-run"
  elif [ "$ROLE_EXISTS" = 1 ]; then
    info "role $DB_ROLE: kept"; note "kept     Postgres role $DB_ROLE"
  else
    case "$dsn_pw" in ''|*[!A-Za-z0-9._~-]*)
      die "role $DB_ROLE is missing and $ENV_OP has no DATABASE_URL of the form postgres://$DB_ROLE:<password>@127.0.0.1:5432/$DB_NAME: create the role by hand";;
    esac
    printf "CREATE ROLE %s LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '%s';\n" "$DB_ROLE" "$dsn_pw" | pg_exec
    ok "role $DB_ROLE created (password from $ENV_OP)"; note "created  Postgres role $DB_ROLE"
  fi
  if [ "$DB_EXISTS" = 1 ]; then
    owner="$(pg_q "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='$DB_NAME'")"
    [ "$owner" = "$DB_ROLE" ] || warn "database $DB_NAME is owned by '$owner', not $DB_ROLE"
    info "database $DB_NAME: kept"; note "kept     Postgres database $DB_NAME"
  else
    printf 'CREATE DATABASE %s OWNER %s;\nREVOKE ALL ON DATABASE %s FROM PUBLIC;\n' "$DB_NAME" "$DB_ROLE" "$DB_NAME" | pg_exec
    ok "database $DB_NAME created (owner $DB_ROLE)"; note "created  Postgres database $DB_NAME"
  fi
  if [ -n "$dsn_pw" ] && [ "$(PGPASSWORD="$dsn_pw" psql -X -q -t -A -h 127.0.0.1 -p 5432 -U "$DB_ROLE" -d "$DB_NAME" -c 'SELECT 1' 2>/dev/null)" = 1 ]; then
    ok "socrate.env's DATABASE_URL signs in to $DB_NAME"
  else
    warn "could not sign in to $DB_NAME with socrate.env's DATABASE_URL: check the role's password"
  fi
  unset dsn_pw
else
  if [ "$ROLE_EXISTS" = 1 ]; then info "role $DB_ROLE: kept"; else plan "create Postgres role $DB_ROLE (LOGIN, password from socrate.env)"; fi
  if [ "$DB_EXISTS" = 1 ]; then info "database $DB_NAME: kept"; else plan "create database $DB_NAME (owner $DB_ROLE, no PUBLIC access)"; fi
fi
info "monitoring BFF sessions stay in memory (BFF_SESSION_DSN unset): no BFF database"

# ---- 7. backups -----------------------------------------------------------------------
step "7/9 backup script"
backup_script() {
  cat <<'EOF'
#!/usr/bin/env bash
# socrate-backup.sh - dump the Socrate database to /var/backups/socrate (written by
# socrate-vps-prep.sh, go-oauth2 deploy/release-kit). Run as root; the last line is the result:
#
#   sudo /usr/local/sbin/socrate-backup.sh | tail -1
#   done: OK /var/backups/socrate/socrate-20261011-031700.sql.gz 1.2M migrations=31
#
# Plain SQL, gzip, mode 0600. Restore: gunzip -c <dump> | sudo -u postgres psql socrate
# Keeps the newest KEEP dumps (default 14). The rows of the monitoring BFF's session tables are
# left out (live OAuth tokens; nothing is skipped when they live in another database). The
# signing keys and env files are not in the dump: keep a copy of them elsewhere.
set -euo pipefail
DB="${DB:-socrate}"
OUT_DIR="${OUT_DIR:-/var/backups/socrate}"
KEEP="${KEEP:-14}"
fail() { echo "done: FAILED $*"; exit 1; }
[ "$(id -u)" = 0 ] || fail "run as root"
case "$KEEP" in ''|*[!0-9]*|0) fail "KEEP must be a positive number";; esac
cd /
umask 077
mkdir -p "$OUT_DIR"
pg() { runuser -u postgres -- "$@"; }
out="$OUT_DIR/$DB-$(date +%Y%m%d-%H%M%S).sql.gz"
echo "dumping $DB to $out"
if ! pg pg_dump --no-password \
    --exclude-table-data=bff_store_sessions --exclude-table-data=bff_store_pending_logins \
    --exclude-table-data=bff_sessions --exclude-table-data=bff_login_states \
    "$DB" | gzip -c > "$out.partial"; then
  rm -f "$out.partial"; fail "pg_dump $DB"
fi
gzip -t "$out.partial" || { rm -f "$out.partial"; fail "gzip -t $out.partial"; }
mv "$out.partial" "$out"
# schema_migrations is Socrate's migration ledger (internal/database/migrate); absent before
# the first start.
if [ "$(pg psql -X -t -A -c "SELECT to_regclass('public.schema_migrations') IS NOT NULL" "$DB" 2>/dev/null)" = t ]; then
  migs="$(pg psql -X -t -A -c 'SELECT count(*) FROM schema_migrations' "$DB" 2>/dev/null)" || migs='?'
else
  migs=0
fi
# shellcheck disable=SC2012 # the dumps' names are this script's own fixed format
ls -1t "$OUT_DIR/$DB"-*.sql.gz 2>/dev/null | tail -n +"$((KEEP + 1))" | while IFS= read -r old; do
  echo "removing $old"; rm -f "$old"
done
echo "done: OK $out $(du -h "$out" | cut -f1) migrations=${migs:-?}"
EOF
}
if [ -e "$R$BACKUP_SCRIPT" ]; then
  if [ "$(cat "$R$BACKUP_SCRIPT")" = "$(backup_script)" ]; then
    info "$BACKUP_SCRIPT: kept (current)"
  else
    if grep -q 'done: OK' "$R$BACKUP_SCRIPT" && grep -q 'migrations=' "$R$BACKUP_SCRIPT"; then
      info "$BACKUP_SCRIPT: kept (not the kit's version)"
    else
      warn "$BACKUP_SCRIPT: kept, but the runbook expects its last line to read 'done: OK ... migrations=<n>'"
    fi
  fi
  note "kept     $BACKUP_SCRIPT"
else
  write_new "$BACKUP_SCRIPT" 0750 root:root "$(backup_script)" || true
fi
backup_cron() {
  cat <<EOF
# $BACKUP_CRON - daily dump of the Socrate database ($MARK).
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
17 3 * * * root $BACKUP_SCRIPT >>/var/log/socrate-backup.log 2>&1
EOF
}
write_new "$BACKUP_CRON" 0644 root:root "$(backup_cron)" || true

# ---- 8. Caddy -------------------------------------------------------------------------
step "8/9 Caddy"
# Exactly the shapes socrate-caddy-update.sh edits: one "@bff path" line per console site, the
# admin CSP as one Content-Security-Policy line in the header block, followed by
# Reporting-Endpoints and Content-Security-Policy-Report-Only in the same form. The admin
# values are those of oauth2-admin's deploy/Caddyfile; the updater replaces them with the
# bundle's on every release. HSTS without "preload": add it only to submit to the preload list.
HSTS='"max-age=31536000; includeSubDomains"'
ADMIN_CSP="default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"
ADMIN_CSP_RO="$ADMIN_CSP; require-trusted-types-for 'script'; trusted-types vue default; report-uri /bff/csp-report; report-to csp"
ADMIN_BFF_PATHS='/bff/* /api/admin/* /api/apps/* /api/profile /api/profile/mfa /api/profile/mfa/* /api/version /api/auth/request-password-reset /api/auth/reset-password'
MON_CSP="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"

main_caddyfile() {
  printf '# %s - main Caddy configuration (%s).\n' "$CADDYFILE" "$MARK"
  printf '# Caddy is the only public listener; each public host has its own file in %s.\n' "$SITES"
  if [ -n "$ACME_EMAIL" ]; then printf '{\n\temail %s\n}\n' "$ACME_EMAIL"; fi
  printf '\nimport %s/*.caddy\n' "$SITES"
}
op_site() {
  cat <<EOF
# $OP_HOST - Socrate OAuth 2.1 / OIDC server ($MARK).
# Only the public OAuth port; the admin API ($ADMIN_API_PORT) has no public route.
# No trusted_proxies: Caddy replaces any client X-Forwarded-For, which Socrate trusts from loopback.
$OP_HOST {
	encode zstd gzip
	header {
		Strict-Transport-Security $HSTS
		X-Content-Type-Options "nosniff"
		Referrer-Policy "strict-origin-when-cross-origin"
		-Server
	}
	reverse_proxy 127.0.0.1:$OP_PORT
}
EOF
}
admin_site() {
  cat <<EOF
# $ADMIN_HOST - Socrate Admin: SPA + admin BFF ($MARK).
# socrate-caddy-update.sh keeps the CSP lines and the @bff matcher in line with each bundle.
$ADMIN_HOST {
	root * /srv/admin/dist

	header {
		Strict-Transport-Security $HSTS
		X-Content-Type-Options "nosniff"
		X-Frame-Options "DENY"
		Referrer-Policy "strict-origin-when-cross-origin"
		Permissions-Policy "geolocation=(), microphone=(), camera=()"
		Cross-Origin-Opener-Policy "same-origin"
		Content-Security-Policy "$ADMIN_CSP"
		Reporting-Endpoints \`csp="/bff/csp-report"\`
		Content-Security-Policy-Report-Only "$ADMIN_CSP_RO"
		-Server
	}

	# The BFF is the only client of the admin API; it allowlists these paths again.
	@bff path $ADMIN_BFF_PATHS
	handle @bff {
		reverse_proxy 127.0.0.1:$ADMIN_BFF_PORT {
			flush_interval -1
			header_up X-Forwarded-Proto {scheme}
		}
	}

	handle {
		try_files {path} /index.html
		file_server
	}
}
EOF
}
mon_site() {
  cat <<EOF
# $MON_HOST - Socrate Monitor: SPA + monitoring BFF ($MARK).
# socrate-caddy-update.sh keeps the @bff matcher in line with each bundle.
$MON_HOST {
	encode zstd gzip
	header {
		Strict-Transport-Security $HSTS
		X-Content-Type-Options "nosniff"
		Referrer-Policy "strict-origin-when-cross-origin"
		Permissions-Policy "geolocation=(), microphone=(), camera=()"
		Content-Security-Policy "$MON_CSP"
		-Server
	}

	# handle, not a bare reverse_proxy: Caddy orders handle blocks before reverse_proxy, so a bare
	# proxy beside the catch-all handle below would never run.
	@bff path /bff/* /api/admin/* /api/version
	handle @bff {
		reverse_proxy 127.0.0.1:$MON_BFF_PORT {
			flush_interval -1
			header_up X-Forwarded-Proto {scheme}
		}
	}

	handle {
		root * /srv/monitoring/dist
		try_files {path} /index.html
		file_server
	}
}
EOF
}

CADDY_NEW=""       # files this run created (removed again if validation fails)
CADDY_REPLACED=""  # the package's default Caddyfile, kept in CADDY_BACKUP
CADDY_BACKUP="/var/backups/socrate/caddy-prep-$STAMP"
CADDY_CHANGED=0
if [ ! -e "$R$CADDYFILE" ]; then
  write_new "$CADDYFILE" 0644 root:root "$(main_caddyfile)" || true
  CADDY_NEW="$CADDYFILE"; CADDY_CHANGED=1
elif grep -qF "$MARK" "$R$CADDYFILE"; then
  info "$CADDYFILE: kept"; note "kept     $CADDYFILE"
elif grep -qF 'root * /usr/share/caddy' "$R$CADDYFILE" && ! grep -qE '^[[:space:]]*import[[:space:]]' "$R$CADDYFILE"; then
  # The Caddy package's welcome page: replaced, with a copy kept.
  if [ "$APPLY" = 1 ]; then
    install -d -m 0700 "$R$CADDY_BACKUP"; cp -a "$R$CADDYFILE" "$R$CADDY_BACKUP/"
    main_caddyfile > "$R$CADDYFILE"; ok "$CADDYFILE: the package's default replaced (copy in $CADDY_BACKUP)"
  else
    plan "replace the Caddy package's default $CADDYFILE (a copy goes to $CADDY_BACKUP)"
  fi
  CADDY_REPLACED="$CADDYFILE"; CADDY_CHANGED=1; note "created  $CADDYFILE (package default replaced)"
else
  info "$CADDYFILE: kept (not written by this script)"; note "kept     $CADDYFILE"
  grep -qE "^[[:space:]]*import[[:space:]]+$SITES/\*\.caddy" "$R$CADDYFILE" \
    || warn "$CADDYFILE does not import $SITES/*.caddy: add 'import $SITES/*.caddy' to it, or the sites below are not served"
fi

# A host already served by another file is left there (a second definition fails validation).
defined_elsewhere() { # host target -> prints the file that defines host, if any
  local re f; re="$(printf '%s' "$1" | sed 's/\./\\./g')"
  for f in "$R$CADDYFILE" "$R$SITES"/*.caddy; do
    [ -f "$f" ] && [ "$f" != "$R$2" ] || continue
    if grep -qE "^[[:space:]]*(https?://)?$re(:[0-9]+)?[[:space:]]*(,|\{|$)" "$f"; then echo "${f#"$R"}"; return; fi
  done
}
site() { # host generator
  local f="$SITES/$1.caddy" other
  other="$(defined_elsewhere "$1" "$f")"
  if [ -n "$other" ] && [ ! -e "$R$f" ]; then
    warn "$1 is already defined in $other: kept there (socrate-caddy-update.sh expects $f for the consoles)"
    note "kept     Caddy site $1 (in $other)"; return
  fi
  if write_new "$f" 0644 root:root "$("$2")"; then CADDY_NEW="$CADDY_NEW $f"; CADDY_CHANGED=1; fi
}
site "$OP_HOST" op_site
site "$ADMIN_HOST" admin_site
site "$MON_HOST" mon_site

if [ "$CADDY_CHANGED" = 1 ] && [ "$APPLY" = 1 ]; then
  vlog="$(mktemp)"
  if ! caddy validate --config "$R$CADDYFILE" --adapter caddyfile >"$vlog" 2>&1; then
    for f in $CADDY_NEW; do rm -f "$R$f"; done
    [ -z "$CADDY_REPLACED" ] || cp -a "$R$CADDY_BACKUP/Caddyfile" "$R$CADDYFILE"
    tail -5 "$vlog" >&2 || true; rm -f "$vlog"
    die "caddy validate failed: the Caddy files written by this run were removed (the env files, users and database are kept; fix and re-run)"
  fi
  rm -f "$vlog"
  ok "caddy validate: OK"
  systemctl is-enabled --quiet caddy 2>/dev/null || systemctl enable --quiet caddy
  systemctl reload-or-restart caddy || die "Caddy reload failed (journalctl -u caddy)"
  ok "Caddy reloaded: certificates are requested as soon as the three names resolve here"
elif [ "$CADDY_CHANGED" = 1 ]; then
  plan "caddy validate, then reload Caddy"
fi
for h in "$OP_HOST" "$ADMIN_HOST" "$MON_HOST"; do
  getent ahosts "$h" >/dev/null 2>&1 || warn "$h does not resolve yet: create its A/AAAA record (Caddy cannot get a certificate before)"
done

# ---- 9. summary -----------------------------------------------------------------------
step "9/9 summary"
if [ "$APPLY" = 1 ]; then echo "  This run:"; else echo "  Plan (dry run, nothing changed; 'created' means 'would create'):"; fi
printf '%s\n' "$SUMMARY" | sed '/^$/d'
[ "$WARNINGS" = 0 ] || echo "  $WARNINGS warning(s) above."
hosts=""
[ "$OP_HOST" = socrate.vandermoten.eu ] && [ "$ADMIN_HOST" = admin.socrate.vandermoten.eu ] && [ "$MON_HOST" = monitor.socrate.vandermoten.eu ] \
  || hosts="OP_HOST=$OP_HOST ADMIN_HOST=$ADMIN_HOST MON_HOST=$MON_HOST "
cat <<EOF

  Next:
    $([ "$APPLY" = 1 ] && echo "0. (done)" || echo "0. sudo bash $0 ... --apply")
    1. Upload the bundle and the kit (RUNBOOK-<tag>.md, step 1), then on this host:
         tar -xzf socrate-suite-<tag>.tar.gz && (cd socrate-suite-<tag> && sha256sum --quiet -c SHA256SUMS)
    2. sudo ${hosts}bash socrate-vps-install.sh ./socrate-suite-<tag>
         first run: migrates, creates the signing keys, asks for the first superadmin, registers
         both console clients (their id and secret replace the placeholders in the BFF env files)
    3. sudo ${hosts}bash socrate-caddy-update.sh ./socrate-suite-<tag>            (dry run)
       sudo ${hosts}bash socrate-caddy-update.sh ./socrate-suite-<tag> --apply
    4. sudo $BACKUP_SCRIPT | tail -1     (expect: done: OK ... migrations=<n>)
    Keep a copy of /etc/socrate/*.env and, after step 2, /var/lib/socrate/keys, off this host.
EOF
