#!/usr/bin/env bash
# socrate-vps-install.sh — install (or upgrade) the new Socrate stack from a release bundle.
# Run as root on the VPS after socrate-vps-prep.sh:
#
#   sudo bash socrate-vps-install.sh ./socrate-suite-v1.4.0
#
# First run: installs binaries, SPAs and units; starts the server once to migrate the empty
# database and create its signing keys; creates the first superadmin (you choose the e-mail and
# password) and the two confidential console clients; starts the consoles; smoke-tests the three
# public hosts. Later runs (upgrades): reinstall from a newer bundle and restart; bootstrap is
# skipped because the clients already exist. The legacy server (socrate-legacy.service) is never
# touched.
set -euo pipefail

BUNDLE="${1:?usage: sudo bash $0 <bundle-dir>}"
OP_HOST="${OP_HOST:-socrate.vandermoten.eu}"
ADMIN_HOST="${ADMIN_HOST:-admin.socrate.vandermoten.eu}"
MON_HOST="${MON_HOST:-monitor.socrate.vandermoten.eu}"
OP_PORT=8080 ADMIN_API_PORT=8082 MON_BFF_PORT=8090 ADMIN_BFF_PORT=8092
ENV_OP=/etc/socrate/socrate.env
ENV_ADMIN=/etc/socrate/admin-bff.env
ENV_MON=/etc/socrate/bff.env
BIN=/usr/local/bin
UNITS=(socrate socrate-admin-bff socrate-monitoring-bff)
BACKUP="/var/backups/socrate/install-$(date +%Y%m%d-%H%M%S)"
PLACEHOLDER=CHANGE_ME_AFTER_CLIENT_REGISTRATION

ok()   { printf '  \033[32m✔\033[0m %s\n' "$*"; }
info() { printf '  · %s\n' "$*"; }
warn() { printf '  \033[33m⚠\033[0m %s\n' "$*"; }
die()  { printf '\033[31m✖ %s\033[0m\n' "$*" >&2; exit 1; }
step() { printf '\n\033[1m▶ %s\033[0m\n' "$*"; }

[ "$(id -u)" = 0 ] || die "run as root: sudo bash $0 <bundle-dir>"

# set_env FILE KEY VALUE — replace or append KEY=VALUE without echoing the value.
set_env() {
  python3 - "$1" "$2" "$3" <<'PY'
import sys, re
path, key, val = sys.argv[1], sys.argv[2], sys.argv[3]
lines = open(path).read().splitlines()
out, done = [], False
for l in lines:
    if re.match(r'^\s*' + re.escape(key) + r'=', l):
        if not done: out.append(f"{key}={val}"); done = True
        continue
    out.append(l)
if not done: out.append(f"{key}={val}")
open(path, "w").write("\n".join(out) + "\n")
PY
}
get_env() { sed -nE "s/^$2=(.*)$/\1/p" "$1" | tail -1; }
json_get() { # KEY — prints the value from JSON on stdin, or nothing (never fails)
  python3 -c 'import sys,json
try: d=json.load(sys.stdin)
except Exception: d={}
v=d.get(sys.argv[1]) if isinstance(d,dict) else None
print("" if v is None else v)' "$1"
}
wait_http() { # URL SECONDS
  local _; for _ in $(seq 1 "$2"); do curl -fsS --max-time 3 -o /dev/null "$1" 2>/dev/null && return 0; sleep 1; done; return 1
}
start_or_die() { # unit health-url
  if ! systemctl restart "$1"; then journalctl -u "$1" -n 40 --no-pager >&2 || true; die "could not start $1"; fi
  if ! wait_http "$2" 60; then journalctl -u "$1" -n 40 --no-pager >&2 || true; die "$1 did not become healthy ($2)"; fi
  ok "$1 healthy ($2)"
}

# Safety net: if the run stops before the lock-down step, switch the admin password login back
# off and restart the server, so an interrupted bootstrap never leaves it enabled.
pwlogin_open=0; locked=0
on_exit() {
  if [ "$pwlogin_open" = 1 ] && [ "$locked" = 0 ]; then
    warn "stopped before lock-down: disabling the admin password login again"
    set_env "$ENV_OP" ADMIN_PASSWORD_LOGIN_ENABLED false || true
    systemctl restart socrate || true
  fi
}
trap on_exit EXIT

# ── 0. Preflight ───────────────────────────────────────────────────────────────────────
step "0/7 preflight"
[ -f "$BUNDLE/SHA256SUMS" ] || die "$BUNDLE/SHA256SUMS not found — pass the unpacked bundle directory"
(cd "$BUNDLE" && sha256sum --quiet -c SHA256SUMS) || die "bundle checksum mismatch"
ok "bundle verified: $(sed -n 1p "$BUNDLE/MANIFEST" | cut -c1-90)"
# Check the whole layout before touching anything: a missing piece found half-way through
# would leave new binaries on disk behind old running processes.
for f in bin/socrate bin/socrate-seed bin/socrate-admin-bff bin/socrate-monitoring-bff \
         www/admin/dist/index.html www/monitoring/dist/index.html \
         systemd/socrate.service systemd/socrate-admin-bff.service systemd/socrate-monitoring-bff.service; do
  [ -s "$BUNDLE/$f" ] || die "bundle is missing $f — nothing was changed"
done
for f in "$ENV_OP" "$ENV_ADMIN" "$ENV_MON"; do [ -f "$f" ] || die "$f missing — run socrate-vps-prep.sh first"; done
for c in python3 curl sha256sum cmp; do command -v "$c" >/dev/null || die "missing command: $c"; done
if systemctl cat socrate.service >/dev/null 2>&1; then
  ex="$(systemctl show -p ExecStart --value socrate.service)"
  case "$ex" in *"$BIN/socrate"*) info "socrate.service already installed (upgrade run)";;
    *) die "socrate.service exists and does not run $BIN/socrate — is the legacy unit still named socrate? ($ex)";; esac
fi
legacy_state="$(systemctl is-active socrate-legacy 2>/dev/null)" || true
info "legacy: socrate-legacy.service is ${legacy_state:-absent} — not touched"
for p in $OP_PORT $ADMIN_API_PORT $MON_BFF_PORT $ADMIN_BFF_PORT; do
  owner="$(ss -ltnpH "sport = :$p" 2>/dev/null | grep -oE 'users:\(\("[^"]+' | cut -d'"' -f2 | head -1)" || true
  case "$owner" in ""|socrate|socrate-admin-b*|socrate-monitor*) ;; *) die "port $p is used by '$owner'";; esac
done
ok "ports free (or held by this stack)"

# ── 1. Binaries, SPAs, units ───────────────────────────────────────────────────────────
step "1/7 install files"
install -d -m 0700 "$BACKUP"
# Record what this backup holds (the running server's /version), and, when this very bundle is
# already installed (a re-run), point the rollback at the newest backup of a different build:
# this run's backup then only holds the new binaries again.
curl -fsS --max-time 3 "http://127.0.0.1:$OP_PORT/version" > "$BACKUP/VERSION" 2>/dev/null || rm -f "$BACKUP/VERSION"
ROLLBACK_FROM="$BACKUP"
if [ -f "$BIN/socrate" ] && cmp -s "$BIN/socrate" "$BUNDLE/bin/socrate"; then
  ROLLBACK_FROM=""
  for d in $(ls -1dt /var/backups/socrate/install-* 2>/dev/null); do
    [ "$d" != "$BACKUP" ] && [ -f "$d/socrate" ] && ! cmp -s "$d/socrate" "$BUNDLE/bin/socrate" && { ROLLBACK_FROM="$d"; break; }
  done
  warn "this bundle is already installed (re-run): roll back from ${ROLLBACK_FROM:-<no earlier backup found>}, not from this run's backup"
fi
for b in socrate socrate-seed socrate-admin-bff socrate-monitoring-bff; do
  [ -f "$BIN/$b" ] && cp -a "$BIN/$b" "$BACKUP/"
  install -m 0755 "$BUNDLE/bin/$b" "$BIN/$b"
done
ok "binaries → $BIN (previous copies in $BACKUP)"
[ -s "$BACKUP/VERSION" ] && info "backed-up server: $(python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); print(v.get("version"), v.get("commit"))' "$BACKUP/VERSION" 2>/dev/null || cat "$BACKUP/VERSION")"
for app in admin monitoring; do
  dst="/srv/$app/dist"
  [ -d "$dst" ] && [ -n "$(ls -A "$dst")" ] && cp -a "$dst" "$BACKUP/$app-dist"
  rm -rf "${dst:?}.new"; cp -r "$BUNDLE/www/$app/dist" "$dst.new"
  chown -R root:root "$dst.new"; find "$dst.new" -type d -exec chmod 0755 {} + -o -type f -exec chmod 0644 {} +
  rm -rf "$dst"; mv "$dst.new" "$dst"
done
ok "SPAs → /srv/admin/dist, /srv/monitoring/dist (root-owned, read-only)"
# Repair the monitor Caddy site written by early versions of socrate-vps-prep.sh: its BFF proxy
# was a bare reverse_proxy, which Caddy orders after the catch-all handle, so /bff/* got the SPA.
MON_SITE="/etc/caddy/sites/$MON_HOST.caddy"
if [ -f "$MON_SITE" ] && grep -qE '^[[:space:]]*reverse_proxy @bff' "$MON_SITE"; then
  cp -a "$MON_SITE" "$BACKUP/"
  python3 - "$MON_SITE" <<'PY'
import sys, re
p = sys.argv[1]; s = open(p).read()
s = re.sub(r'(\t@bff path [^\n]*\n)\treverse_proxy @bff ([^{]+)\{\n((?:\t\t[^\n]*\n)*)\t\}\n',
           lambda m: m.group(1) + "\thandle @bff {\n\t\treverse_proxy " + m.group(2) + "{\n"
                     + "".join("\t" + l + "\n" for l in m.group(3).splitlines()) + "\t\t}\n\t}\n", s)
open(p, "w").write(s)
PY
  if caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1; then
    systemctl reload caddy; ok "monitor Caddy site repaired (BFF routes now reach the BFF); Caddy reloaded"
  else
    cp -a "$BACKUP/$(basename "$MON_SITE")" "$MON_SITE"; die "repairing $MON_SITE failed validation — restored"
  fi
fi
for u in "${UNITS[@]}"; do install -m 0644 "$BUNDLE/systemd/$u.service" "/etc/systemd/system/$u.service"; done
systemctl daemon-reload
ok "units installed: ${UNITS[*]}"
cp -a "$ENV_OP" "$ENV_ADMIN" "$ENV_MON" "$BACKUP/"

# ── 2. Server: first start / restart ───────────────────────────────────────────────────
step "2/7 server"
need_bootstrap=0
[ "$(get_env "$ENV_ADMIN" BFF_CLIENT_SECRET)" = "$PLACEHOLDER" ] && need_bootstrap=1
[ "$(get_env "$ENV_MON" BFF_CLIENT_SECRET)" = "$PLACEHOLDER" ] && need_bootstrap=1
set_env "$ENV_OP" AUTO_MIGRATE true   # applies any new migration (first run: all of them); off again at lock-down
if [ "$need_bootstrap" = 1 ]; then
  # The admin password login is needed once, on loopback only, to create the console clients.
  set_env "$ENV_OP" ADMIN_PASSWORD_LOGIN_ENABLED true; pwlogin_open=1
  info "first run: admin password login enabled temporarily (loopback admin API only)"
fi
start_or_die socrate "http://127.0.0.1:$OP_PORT/health/readiness"
wait_http "http://127.0.0.1:$ADMIN_API_PORT/health" 20 || die "admin API not answering on 127.0.0.1:$ADMIN_API_PORT"
ok "admin API on 127.0.0.1:$ADMIN_API_PORT"
migs="$(sudo -u postgres psql -XtAc "SELECT count(*) FROM schema_migrations" socrate 2>/dev/null || echo '?')"
info "schema migrations applied: $migs; signing keys: $(ls /var/lib/socrate/keys | tr '\n' ' ')"

# ── 3. Bootstrap: superadmin + console clients ────────────────────────────────────────
step "3/7 bootstrap"
if [ "$need_bootstrap" = 0 ]; then
  info "console clients already configured — skipped"
else
  ADM="http://127.0.0.1:$ADMIN_API_PORT"
  login() { # email password -> JSON login response (empty on failure)
    python3 -c 'import json,sys; print(json.dumps({"email":sys.argv[1],"password":sys.argv[2]}))' "$1" "$2" \
      | curl -fsS -H 'Content-Type: application/json' --data @- "$ADM/api/admin/login" 2>/dev/null || true
  }
  # Interactive by default. For an unattended run, set SA_EMAIL, SA_NAME and SA_PASSWORD.
  SA_EMAIL="${SA_EMAIL:-}"; SA_NAME="${SA_NAME:-}"; SA_PW="${SA_PASSWORD:-}"
  [ -n "$SA_EMAIL" ] || read -r -p "  Superadmin e-mail: " SA_EMAIL </dev/tty
  [ -n "$SA_NAME" ]  || read -r -p "  Superadmin display name: " SA_NAME </dev/tty
  if [ -n "$SA_PW" ]; then
    [ "${#SA_PW}" -ge 12 ] || die "SA_PASSWORD must be at least 12 characters"
  else
    while :; do
      read -r -s -p "  Choose the superadmin password (min 12 chars): " SA_PW </dev/tty; echo
      read -r -s -p "  Repeat it: " SA_PW2 </dev/tty; echo
      [ "$SA_PW" = "$SA_PW2" ] && [ "${#SA_PW}" -ge 12 ] && break
      warn "passwords differ or are shorter than 12 characters — try again"
    done
  fi
  resp="$(login "$SA_EMAIL" "$SA_PW")"
  if [ -n "$resp" ] && [ "$(json_get must_change_password <<<"$resp")" != "True" ]; then
    info "superadmin $SA_EMAIL already exists with this password — reused (resumed run)"
  else
    tmp_pw="$(openssl rand -base64 24)"
    # socrate-seed reads the server env; the temporary password is replaced right below.
    sudo -u socrate bash -c "set -a; . '$ENV_OP'; set +a; exec '$BIN/socrate-seed' -email \"\$1\" -name \"\$2\" -password \"\$3\"" _ \
      "$SA_EMAIL" "$SA_NAME" "$tmp_pw" >/dev/null \
      || die "socrate-seed failed — if $SA_EMAIL already exists with another password, re-run and enter that password"
    ok "superadmin $SA_EMAIL created"
    tok="$(login "$SA_EMAIL" "$tmp_pw" | json_get access_token)"
    [ -n "$tok" ] || die "login with the seeded account failed"
    python3 -c 'import json,sys; print(json.dumps({"current_password":sys.argv[1],"new_password":sys.argv[2]}))' "$tmp_pw" "$SA_PW" \
      | curl -fsS -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' --data @- "$ADM/api/admin/change-password" >/dev/null \
      || die "setting your password failed (the server's password policy may reject it — re-run with a stronger one)"
    unset tmp_pw
    resp="$(login "$SA_EMAIL" "$SA_PW")"
  fi
  tok="$(json_get access_token <<<"$resp")"
  [ -n "$tok" ] || die "login with your password failed"
  ok "password set; logged in on the loopback admin API"

  create_client() { # name host -> "client_id client_secret"
    python3 -c 'import json,sys; h=sys.argv[2]; print(json.dumps({"name":sys.argv[1],"url":"https://"+h,
      "redirect_uris":["https://"+h+"/bff/callback"],"is_public":False,"require_pkce":True}))' "$1" "$2" \
      | curl -fsS -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' --data @- "$ADM/api/admin/apps" \
      | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["client_id"], d["client_secret"])'
  }
  # Each client is saved to its env file as soon as it exists, so a re-run never duplicates one.
  register() { # env-file name host
    if [ "$(get_env "$1" BFF_CLIENT_SECRET)" != "$PLACEHOLDER" ]; then info "$2: already registered ($(get_env "$1" BFF_CLIENT_ID))"; return; fi
    local id="" secret=""; read -r id secret < <(create_client "$2" "$3") || true
    [ -n "${secret:-}" ] || die "registering $2 failed"
    set_env "$1" BFF_CLIENT_ID "$id"; set_env "$1" BFF_CLIENT_SECRET "$secret"
    ok "$2 registered: client_id $id (secret written to $1 only)"
  }
  register "$ENV_ADMIN" "Socrate Admin (BFF)" "$ADMIN_HOST"
  register "$ENV_MON" "Socrate Monitor (BFF)" "$MON_HOST"
  unset SA_PW SA_PW2 SA_PASSWORD tok resp
fi

# ── 4. Lock down and restart the server ───────────────────────────────────────────────
step "4/7 lock down"
set_env "$ENV_OP" ADMIN_PASSWORD_LOGIN_ENABLED false
set_env "$ENV_OP" AUTO_MIGRATE false
locked=1
chown root:socrate "$ENV_OP"; chmod 0640 "$ENV_OP"
chown root:socrate-admin-bff "$ENV_ADMIN"; chmod 0640 "$ENV_ADMIN"
chown root:socrate-mon-bff "$ENV_MON"; chmod 0640 "$ENV_MON"
start_or_die socrate "http://127.0.0.1:$OP_PORT/health/readiness"
code="$(curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -d '{}' "http://127.0.0.1:$ADMIN_API_PORT/api/admin/login")" || true
[ "$code" = 403 ] || [ "$code" = 404 ] || [ "$code" = 410 ] && ok "admin password login is off (HTTP $code)" || warn "admin password login answered $code — expected it to be refused"
ok "AUTO_MIGRATE=false, ADMIN_PASSWORD_LOGIN_ENABLED=false"

# ── 5. Consoles ───────────────────────────────────────────────────────────────────────
step "5/7 consoles"
start_or_die socrate-admin-bff "http://127.0.0.1:$ADMIN_BFF_PORT/bff/healthz"
start_or_die socrate-monitoring-bff "http://127.0.0.1:$MON_BFF_PORT/bff/healthz"
systemctl enable "${UNITS[@]}" >/dev/null 2>&1 && ok "enabled at boot: ${UNITS[*]}"

# ── 6. Smoke tests through Caddy (public HTTPS) ───────────────────────────────────────
step "6/7 smoke tests"
fails=0
check() { # label expected-code url [grep-pattern]
  local body code; body="$(curl -s --max-time 10 -w '\n%{http_code}' "$3" || true)"; code="${body##*$'\n'}"
  if [ "$code" = "$2" ] && { [ -z "${4:-}" ] || grep -q "$4" <<<"$body"; }; then ok "$1 ($code)"
  else warn "$1: got $code, expected $2${4:+ with '$4'}"; fails=$((fails+1)); fi
}
check "discovery issuer"            200 "https://$OP_HOST/.well-known/openid-configuration" "\"issuer\":\"https://$OP_HOST\""
check "JWKS"                        200 "https://$OP_HOST/.well-known/jwks.json" '"kty":"RSA"'
check "admin API not public"        404 "https://$OP_HOST/api/admin/stats"
check "admin console SPA"           200 "https://$ADMIN_HOST/"
check "admin BFF session (anon)"    200 "https://$ADMIN_HOST/bff/session" '"authenticated":false'
check "monitor console SPA"         200 "https://$MON_HOST/"
check "monitor BFF session (anon)"  200 "https://$MON_HOST/bff/session" '"authenticated":false'
for h in "$ADMIN_HOST" "$MON_HOST"; do
  loc="$(curl -s -o /dev/null -w '%{redirect_url}' --max-time 10 "https://$h/bff/login")" || true
  case "$loc" in "https://$OP_HOST/oauth/authorize?"*code_challenge_method=S256*) ok "https://$h/bff/login → authorize with PKCE";;
    *) warn "https://$h/bff/login redirected to '${loc:-nothing}'"; fails=$((fails+1));; esac
done
lc="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 https://golfperformance.fr/.well-known/openid-configuration || true)"
[ "$lc" = 200 ] && ok "legacy discovery on golfperformance.fr still 200" || warn "legacy discovery answered $lc"

# ── 7. Summary ────────────────────────────────────────────────────────────────────────
step "7/7 summary"
if [ "$fails" = 0 ]; then ok "all smoke tests passed"; else warn "$fails smoke test(s) failed — see above"; fi
cat <<EOF

  Socrate (issuer)   https://$OP_HOST
  Socrate Admin      https://$ADMIN_HOST        sign in with the superadmin you just created
  Socrate Monitor    https://$MON_HOST
  Services           systemctl status ${UNITS[*]}
  Logs               journalctl -u socrate -f
  Backup of this run $BACKUP  (previous binaries, SPAs and env files)
  Roll back from     ${ROLLBACK_FROM:-<no earlier backup found>}  ($( [ -s "${ROLLBACK_FROM:-/nonexistent}/VERSION" ] && python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); print(v.get("version"), v.get("commit"))' "$ROLLBACK_FROM/VERSION" 2>/dev/null || echo "version not recorded"))

  Next: sign in to the admin console; enable MFA for your account; then migrate applications
  one at a time (deploy/migration/ in go-oauth2).
EOF
