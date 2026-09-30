#!/usr/bin/env bash
# socrate-apps-access.sh — let the apps VPS use Socrate from another host. Run as root on the
# SOCRATE VPS:
#
#   sudo bash socrate-apps-access.sh --apps-ip 135.125.107.71 --key 'ssh-ed25519 AAAA… apps-tunnel'
#   sudo bash socrate-apps-access.sh --apps-ip 135.125.107.71 --key '…' --apply
#
# The first form is a dry run (shows the plan, changes nothing).
#
# Two changes, both idempotent, both limited to that one apps address:
#   1. Caddy: `trusted_proxies static <apps-ip>` in the global `servers` options, so the browser IP
#      an app sets in X-Forwarded-For (backendkit client attribution) reaches Socrate. Requests from
#      any other address are unchanged: Caddy keeps overwriting their X-Forwarded-For.
#   2. SSH: a no-shell system user (apps-tunnel) whose single key may only open a forward to the
#      loopback admin API (127.0.0.1:8082), only from <apps-ip>. The apps VPS runs the tunnel
#      (apps-socrate-tunnel.sh); apps then call the admin API at http://127.0.0.1:18082 locally.
# The admin API stays bound to loopback; nothing about Socrate itself changes. sshd_config is only
# read, never edited (a mistake there can lock you out): anything blocking the tunnel is reported.
set -euo pipefail

APPS_IP=""; KEY=""; APPLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --apps-ip) APPS_IP="${2:-}"; shift 2 ;;
    --key)     KEY="${2:-}"; shift 2 ;;
    --apply)   APPLY=1; shift ;;
    *) printf 'usage: %s --apps-ip <ip> --key "<ssh-ed25519 public key>" [--apply]\n' "$0" >&2; exit 2 ;;
  esac
done
CADDYFILE="${CADDYFILE:-/etc/caddy/Caddyfile}"
TUNNEL_USER="${TUNNEL_USER:-apps-tunnel}"
ADMIN_API_PORT="${ADMIN_API_PORT:-8082}"
BACKUP="/var/backups/socrate/apps-access-$(date +%Y%m%d-%H%M%S)"

ok()   { printf '  \033[32m✔\033[0m %s\n' "$*"; }
info() { printf '  · %s\n' "$*"; }
warn() { printf '  \033[33m⚠\033[0m %s\n' "$*"; }
die()  { printf '\033[31m✖ %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root"
[ -n "$APPS_IP" ] && [ -n "$KEY" ] || die "usage: $0 --apps-ip <ip> --key \"<ssh-ed25519 public key>\" [--apply]"
for c in caddy sshd ssh-keygen python3 curl useradd; do command -v "$c" >/dev/null || die "missing command: $c"; done
[ -f "$CADDYFILE" ] || die "$CADDYFILE not found"
CADDY_V="$(caddy version 2>/dev/null | awk '{print $1}')"
python3 -c 'import re,sys; m=re.match(r"v?(\d+)\.(\d+)\.(\d+)", sys.argv[1]); sys.exit(0 if m and tuple(map(int,m.groups()))>=(2,6,3) else 1)' "$CADDY_V" \
  || die "Caddy ${CADDY_V:-?} has no global trusted_proxies option (needs v2.6.3 or later) — upgrade Caddy first; nothing changed"

# ── inputs ────────────────────────────────────────────────────────────────────────────────
APPS_CIDR="$(python3 -c 'import ipaddress,sys; a=ipaddress.ip_address(sys.argv[1]); print(f"{a}/{32 if a.version==4 else 128}")' "$APPS_IP" 2>/dev/null)" \
  || die "--apps-ip '$APPS_IP' is not an IP address"
APPS_IP="${APPS_CIDR%/*}"
case "$KEY" in *$'\n'*) die "--key must be one line";; esac
set -- $KEY
[ "${1:-}" = ssh-ed25519 ] && [ -n "${2:-}" ] || die "--key must be an ssh-ed25519 public key ('ssh-ed25519 AAAA… comment')"
KEY_LINE="$1 $2 ${3:-apps-tunnel}"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
printf '%s\n' "$KEY_LINE" > "$tmp/key.pub"
KEY_FP="$(ssh-keygen -lf "$tmp/key.pub" 2>/dev/null | awk '{print $2}')" || true
[ -n "$KEY_FP" ] || die "--key is not a valid public key"
code="$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$ADMIN_API_PORT/health/liveness" || true)"
[ "$code" = 200 ] || die "the Socrate admin API does not answer on 127.0.0.1:$ADMIN_API_PORT (got $code) — set ADMIN_API_PORT"

printf '\n\033[1m▶ plan\033[0m  apps VPS %s, key %s\n' "$APPS_CIDR" "$KEY_FP"

# ── 1. Caddy global trusted_proxies ───────────────────────────────────────────────────────
python3 - "$CADDYFILE" "$tmp/Caddyfile" "$APPS_CIDR" >/dev/null <<'CADDYPY'
import re, sys
src, out, cidr = sys.argv[1:4]
lines = open(src).read().splitlines(True)

def depth_change(l):
    s = re.sub(r'"(?:\\.|[^"\\])*"|`[^`]*`', '', l.split('#', 1)[0] if not l.lstrip().startswith('#') else '')
    return s.count('{') - s.count('}')

# The global options block is a bare "{" as the first significant line of the file.
first = next((i for i, l in enumerate(lines) if l.strip() and not l.strip().startswith('#')), None)
if first is None or lines[first].strip() != '{':
    block = ['{\n', '\tservers {\n', f'\t\ttrusted_proxies static {cidr}\n', '\t}\n', '}\n', '\n']
    open(out, 'w').write(''.join(block + lines)); print('create'); sys.exit()
d, end = 0, None
for i in range(first, len(lines)):
    d += depth_change(lines[i])
    if d == 0: end = i; break
if end is None: sys.exit('unbalanced braces in the global options block')
glob = range(first + 1, end)
servers = [i for i in glob if re.match(r'\s*servers\b', lines[i])]
if not servers:
    lines[end:end] = ['\tservers {\n', f'\t\ttrusted_proxies static {cidr}\n', '\t}\n']
    open(out, 'w').write(''.join(lines)); print('add-servers'); sys.exit()
if len(servers) > 1 or not re.match(r'\s*servers\s*\{\s*$', lines[servers[0]]):
    sys.exit('the global options have a per-listener or repeated "servers" block — add the trusted_proxies line by hand')
s = servers[0]; d, s_end = 0, None
for i in range(s, end):
    d += depth_change(lines[i])
    if d == 0: s_end = i; break
tp = [i for i in range(s + 1, s_end) if re.match(r'\s*trusted_proxies\b', lines[i])]
if not tp:
    indent = re.match(r'(\s*)', lines[s]).group(1)
    lines[s_end:s_end] = [f'{indent}\ttrusted_proxies static {cidr}\n']
    open(out, 'w').write(''.join(lines)); print('add-line'); sys.exit()
l = lines[tp[0]]
words = l.split()
if len(tp) > 1 or len(words) < 2 or words[1] != 'static' or l.rstrip().endswith('{'):
    sys.exit('trusted_proxies is not a single "trusted_proxies static …" line — edit it by hand')
if cidr in words[2:] or cidr.split('/')[0] in words[2:]:
    open(out, 'w').write(''.join(lines)); print('present'); sys.exit()
lines[tp[0]] = l.rstrip('\n') + f' {cidr}\n'
open(out, 'w').write(''.join(lines)); print('extend')
CADDYPY
caddy_change=0
if cmp -s "$CADDYFILE" "$tmp/Caddyfile"; then ok "Caddy already trusts $APPS_CIDR"; else
  caddy_change=1; info "Caddy ($CADDYFILE):"; { diff -u "$CADDYFILE" "$tmp/Caddyfile" | sed -n '3,$p' | grep '^[-+]' | sed 's/^/      /'; } || true
  caddy adapt --config "$tmp/Caddyfile" --adapter caddyfile >/dev/null 2>"$tmp/adapt.err" || { sed 's/^/      /' "$tmp/adapt.err" | tail -3; die "the edited Caddyfile does not parse — nothing changed"; }
fi

# ── 2. the tunnel user and its key ────────────────────────────────────────────────────────
AUTH_LINE="restrict,port-forwarding,from=\"$APPS_IP\",permitopen=\"127.0.0.1:$ADMIN_API_PORT\",command=\"/usr/sbin/nologin\" $KEY_LINE"
user_new=0; key_change=0
if id "$TUNNEL_USER" >/dev/null 2>&1; then
  [ "$(getent passwd "$TUNNEL_USER" | cut -d: -f7)" = /usr/sbin/nologin ] || die "user $TUNNEL_USER exists with a login shell — choose another TUNNEL_USER"
  ok "user $TUNNEL_USER exists (no shell)"
else user_new=1; info "create system user $TUNNEL_USER (shell /usr/sbin/nologin, no password)"; fi
HOME_DIR="$(getent passwd "$TUNNEL_USER" | cut -d: -f6 || true)"; HOME_DIR="${HOME_DIR:-/var/lib/$TUNNEL_USER}"
# Where sshd looks for this user's keys (first entry of AuthorizedKeysFile, with %h/%u/%% expanded).
SSHD_T="$(sshd -T -C "user=$TUNNEL_USER,host=apps,addr=$APPS_IP" 2>/dev/null)" || die "sshd -T failed — is the sshd configuration valid?"
akf="$(awk '$1=="authorizedkeysfile"{print $2; exit}' <<<"$SSHD_T")"; akf="${akf:-.ssh/authorized_keys}"
akf="${akf//%h/$HOME_DIR}"; akf="${akf//%u/$TUNNEL_USER}"; akf="${akf//%%/%}"; case "$akf" in /*) ;; *) akf="$HOME_DIR/$akf";; esac
if [ -f "$akf" ] && [ "$(cat "$akf")" = "$AUTH_LINE" ]; then ok "key $KEY_FP already authorised in $akf"; else
  key_change=1; info "authorise the key in $akf (replacing any other key):"; info "    ${AUTH_LINE:0:150}…"; fi

# ── 3. sshd lets it through? (read-only) ──────────────────────────────────────────────────
blockers=0
fwd="$(awk '$1=="allowtcpforwarding"{print $2}' <<<"$SSHD_T")"; dis="$(awk '$1=="disableforwarding"{print $2}' <<<"$SSHD_T")"
case "$fwd" in yes|local|all) ;; *) blockers=1; warn "sshd: AllowTcpForwarding is '$fwd' for $TUNNEL_USER — needs 'local' (a Match User $TUNNEL_USER block can grant it)";; esac
[ "$dis" != yes ] || { blockers=1; warn "sshd: DisableForwarding yes — the tunnel cannot work"; }
au="$(awk '$1=="allowusers"{ $1=""; print }' <<<"$SSHD_T")"; ag="$(awk '$1=="allowgroups"{ $1=""; print }' <<<"$SSHD_T")"
if [ -n "${au// }" ] && ! grep -qwE "$TUNNEL_USER(@[^ ]*)?" <<<"$au"; then blockers=1; warn "sshd: AllowUsers is set ($au) — add '$TUNNEL_USER@$APPS_IP' to it"; fi
[ -z "${ag// }" ] || warn "sshd: AllowGroups is set ($ag) — make sure $TUNNEL_USER is in one of them"
pk="$(awk '$1=="pubkeyauthentication"{print $2}' <<<"$SSHD_T")"; [ "$pk" = yes ] || { blockers=1; warn "sshd: PubkeyAuthentication is '$pk'"; }
am="$(awk '$1=="authenticationmethods"{ $1=""; print }' <<<"$SSHD_T")"
case "${am// }" in ""|any|publickey) ;; *) blockers=1; warn "sshd: AuthenticationMethods '$am' — the tunnel only has a key";; esac
[ "$blockers" = 0 ] && ok "sshd allows key login and local forwarding for $TUNNEL_USER from $APPS_IP"
HOST_FP="$(ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null | awk '{print $2}')" || true
[ -n "$HOST_FP" ] || die "no ed25519 host key (/etc/ssh/ssh_host_ed25519_key.pub)"

if [ "$caddy_change$user_new$key_change" = 000 ]; then printf '\nNothing to change.\n'
elif [ "$APPLY" = 0 ]; then printf '\nDry run only. Re-run with --apply.\n'; fi
if [ "$APPLY" = 1 ] && [ "$caddy_change$user_new$key_change" != 000 ]; then
  printf '\n\033[1m▶ apply\033[0m\n'
  install -d -m 0700 "$BACKUP"; cp -a "$CADDYFILE" "$BACKUP/"; [ -f "$akf" ] && cp -a "$akf" "$BACKUP/authorized_keys"
  ok "backup in $BACKUP"
  if [ "$user_new" = 1 ]; then
    useradd --system --home-dir "$HOME_DIR" --create-home --shell /usr/sbin/nologin --comment "Socrate admin API tunnel for the apps VPS" "$TUNNEL_USER"
    ok "user $TUNNEL_USER created"
  fi
  if [ "$key_change" = 1 ]; then
    install -d -m 0700 -o "$TUNNEL_USER" -g "$TUNNEL_USER" "$(dirname "$akf")"
    printf '%s\n' "$AUTH_LINE" > "$akf.new"; chown "$TUNNEL_USER:$TUNNEL_USER" "$akf.new"; chmod 0600 "$akf.new"; mv "$akf.new" "$akf"
    ok "key authorised in $akf"
  fi
  if [ "$caddy_change" = 1 ]; then
    cat "$tmp/Caddyfile" > "$CADDYFILE"
    if ! caddy validate --config "$CADDYFILE" --adapter caddyfile >"$tmp/validate.log" 2>&1; then
      cp -a "$BACKUP/$(basename "$CADDYFILE")" "$CADDYFILE"; tail -5 "$tmp/validate.log" >&2; die "caddy validate failed — Caddyfile restored, Caddy not reloaded"
    fi
    if ! systemctl reload caddy || ! systemctl is-active --quiet caddy; then
      cp -a "$BACKUP/$(basename "$CADDYFILE")" "$CADDYFILE"; systemctl reload caddy || true; die "Caddy reload failed — Caddyfile restored"
    fi
    ok "Caddy validated and reloaded"
  fi
  printf '\nTo undo: cp %s/%s %s && systemctl reload caddy; userdel -r %s\n' "$BACKUP" "$(basename "$CADDYFILE")" "$CADDYFILE" "$TUNNEL_USER"
fi

printf '\n\033[1m▶ next, on the apps VPS\033[0m\n'
printf '  sudo bash apps-socrate-tunnel.sh install %s --apply\n' "$HOST_FP"
printf '  (%s is this host'"'"'s ed25519 SSH host key; the apps side pins it)\n' "$HOST_FP"
[ "$blockers" = 0 ] || printf '\n\033[33mFix the sshd warnings above first, or the tunnel will be refused.\033[0m\n'
