#!/usr/bin/env bash
# apps-socrate-tunnel.sh — reach the Socrate admin API from the apps VPS. Run as root on the APPS VPS.
#
#   sudo bash apps-socrate-tunnel.sh key
#       Creates the tunnel's SSH key (once) and prints its public key.
#       Hand the public key to socrate-apps-access.sh on the Socrate VPS.
#   sudo bash apps-socrate-tunnel.sh install SHA256:<socrate-host-key-fp> [--apply]
#       Pins Socrate's SSH host key (the fingerprint socrate-apps-access.sh printed) and installs
#       and starts socrate-admin-tunnel.service. Without --apply it is a dry run.
#       Then it checks what the tunnel allows and refuses.
#   sudo bash apps-socrate-tunnel.sh verify
#       Re-runs those checks.
#
# The tunnel forwards 127.0.0.1:18082 on this host to 127.0.0.1:8082 (the loopback-only admin API)
# on the Socrate VPS. Apps set SOCRATE_ADMIN_URL=http://127.0.0.1:18082. The OAuth endpoints stay
# on https://socrate.vandermoten.eu; do not route them through the tunnel.
# The SSH key can open that one forward and nothing else (no shell, no other port — enforced on the
# Socrate side). If the tunnel is down, admin calls fail (no fallback); systemd restarts it within
# seconds.
set -euo pipefail

CMD="${1:-}"; shift || true
SOCRATE_SSH_HOST="${SOCRATE_SSH_HOST:-socrate.vandermoten.eu}"
SOCRATE_SSH_PORT="${SOCRATE_SSH_PORT:-22}"
TUNNEL_USER="${TUNNEL_USER:-apps-tunnel}"
LOCAL_PORT="${LOCAL_PORT:-18082}"
REMOTE_PORT="${REMOTE_PORT:-8082}"
DIR="${DIR:-/etc/socrate-tunnel}"
RUN_AS="${RUN_AS:-socrate-tunnel}"
UNIT=socrate-admin-tunnel
UNIT_FILE="/etc/systemd/system/$UNIT.service"
KEY="$DIR/id_ed25519"
KNOWN="$DIR/known_hosts"

ok()   { printf '  \033[32m✔\033[0m %s\n' "$*"; }
info() { printf '  · %s\n' "$*"; }
warn() { printf '  \033[33m⚠\033[0m %s\n' "$*"; }
die()  { printf '\033[31m✖ %s\033[0m\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root"
for c in ssh ssh-keygen ssh-keyscan curl systemctl; do command -v "$c" >/dev/null || die "missing command: $c"; done

ensure_runner() {
  id "$RUN_AS" >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin \
    --comment "Socrate admin API tunnel" "$RUN_AS"
  install -d -m 0750 -o root -g "$RUN_AS" "$DIR"
}
# ssh as the tunnel runner, with only our files (no user or system ssh_config).
tssh() {
  local p=(-F none -i "$KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o UserKnownHostsFile="$KNOWN" \
    -o StrictHostKeyChecking=yes -o ConnectTimeout=10 -p "$SOCRATE_SSH_PORT")
  if command -v runuser >/dev/null; then runuser -u "$RUN_AS" -- ssh "${p[@]}" "$@"; else ssh "${p[@]}" "$@"; fi
}

verify() {
  printf '\n\033[1m▶ verify\033[0m\n'
  local fails=0 body code
  systemctl is-active --quiet "$UNIT" && ok "$UNIT is active" || { warn "$UNIT is not active"; fails=1; }
  for _ in $(seq 1 15); do body="$(curl -s --noproxy '*' --max-time 3 "http://127.0.0.1:$LOCAL_PORT/version" || true)"; [ -n "$body" ] && break; sleep 1; done
  case "$body" in \{*\"version\"*) ok "admin API through the tunnel: $body";; *) warn "no answer on 127.0.0.1:$LOCAL_PORT/version"; fails=1;; esac
  code="$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' --max-time 5 -X POST -H 'Content-Type: application/json' -d '{}' "http://127.0.0.1:$LOCAL_PORT/api/admin/login" || true)"
  case "$code" in 4??) ok "admin endpoints answer and require credentials (POST /api/admin/login → $code)";; *) warn "POST /api/admin/login → '$code'"; fails=1;; esac
  # Refusals, enforced by the Socrate side: no shell, no other forward.
  if tssh "$TUNNEL_USER@$SOCRATE_SSH_HOST" true >/dev/null 2>&1; then warn "the key can run a command on the Socrate VPS — its restrictions are missing"; fails=1
  else ok "the key cannot run a shell or a command"; fi
  local probe=$((LOCAL_PORT + 17)) pid
  tssh -N -o ExitOnForwardFailure=yes -L "127.0.0.1:$probe:127.0.0.1:8080" "$TUNNEL_USER@$SOCRATE_SSH_HOST" >/dev/null 2>&1 & pid=$!
  sleep 3; code="$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$probe/version" || true)"
  kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
  case "$code" in 000|"") ok "the key cannot forward to any other port (8080 refused)";; *) warn "a forward to 8080 answered $code — permitopen is missing"; fails=1;; esac
  [ "$fails" = 0 ] && printf '\nApps: SOCRATE_ADMIN_URL=http://127.0.0.1:%s\n' "$LOCAL_PORT" || die "verification failed"
}

case "$CMD" in
key)
  ensure_runner
  if [ -f "$KEY" ]; then ok "key exists: $KEY"; else
    ssh-keygen -q -t ed25519 -N '' -C "apps-tunnel@$(hostname -s)" -f "$KEY"
    chown root:"$RUN_AS" "$KEY" "$KEY.pub"; chmod 0640 "$KEY"; chmod 0644 "$KEY.pub"
    ok "key created: $KEY"
  fi
  printf '\nPublic key — pass it to socrate-apps-access.sh on the Socrate VPS (--key '"'"'…'"'"'):\n\n%s\n' "$(cat "$KEY.pub")"
  ;;
install)
  FP="${1:-}"; APPLY=0; [ "${2:-}" = --apply ] && APPLY=1
  case "$FP" in SHA256:?*) ;; *) die "usage: $0 install SHA256:<socrate-host-key-fp> [--apply]";; esac
  [ -f "$KEY" ] || die "no key yet — run: $0 key"
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  ssh-keyscan -T 10 -t ed25519 -p "$SOCRATE_SSH_PORT" "$SOCRATE_SSH_HOST" 2>/dev/null > "$tmp/known" || true
  [ -s "$tmp/known" ] || die "could not read $SOCRATE_SSH_HOST:$SOCRATE_SSH_PORT's host key"
  got="$(ssh-keygen -lf "$tmp/known" | awk '{print $2}')"
  [ "$got" = "$FP" ] || die "host key mismatch: $SOCRATE_SSH_HOST presents $got, expected $FP — stop, do not continue"
  ok "Socrate host key matches $FP"
  if ss -ltnH "sport = :$LOCAL_PORT" 2>/dev/null | grep -q . && ! systemctl is-active --quiet "$UNIT"; then die "port $LOCAL_PORT is already in use"; fi
  cat > "$tmp/unit" <<EOF
[Unit]
Description=SSH tunnel to the Socrate admin API (127.0.0.1:$LOCAL_PORT -> $SOCRATE_SSH_HOST 127.0.0.1:$REMOTE_PORT)
After=network-online.target
Wants=network-online.target

[Service]
User=$RUN_AS
ExecStart=/usr/bin/ssh -N -F none -i $KEY -o IdentitiesOnly=yes -o BatchMode=yes -o UserKnownHostsFile=$KNOWN -o StrictHostKeyChecking=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -p $SOCRATE_SSH_PORT -L 127.0.0.1:$LOCAL_PORT:127.0.0.1:$REMOTE_PORT $TUNNEL_USER@$SOCRATE_SSH_HOST
Restart=always
RestartSec=5
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
EOF
  changed=0
  cmp -s "$tmp/known" "$KNOWN" 2>/dev/null && ok "host key already pinned in $KNOWN" || { changed=1; info "pin the host key in $KNOWN"; }
  cmp -s "$tmp/unit" "$UNIT_FILE" 2>/dev/null && ok "$UNIT_FILE up to date" || { changed=1; info "install $UNIT_FILE (127.0.0.1:$LOCAL_PORT → $SOCRATE_SSH_HOST:127.0.0.1:$REMOTE_PORT)"; }
  if [ "$APPLY" = 0 ]; then [ "$changed" = 1 ] && printf '\nDry run only. Re-run with --apply.\n' || printf '\nNothing to change.\n'; exit 0; fi
  ensure_runner
  install -m 0644 -o root -g "$RUN_AS" "$tmp/known" "$KNOWN"
  install -m 0644 "$tmp/unit" "$UNIT_FILE"
  systemctl daemon-reload
  systemctl enable "$UNIT" >/dev/null 2>&1 || true
  systemctl restart "$UNIT"
  ok "$UNIT installed, enabled and (re)started"
  verify
  ;;
verify) verify ;;
*) die "usage: $0 key | install SHA256:<fp> [--apply] | verify" ;;
esac
