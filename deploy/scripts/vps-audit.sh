#!/usr/bin/env bash
# vps-audit.sh — READ-ONLY pre/post-deploy audit of a Socrate VPS.
#
# Makes NO changes. Run on the VPS:  sudo bash vps-audit.sh
# Prints PASS / WARN / FAIL per check; investigate every WARN and FAIL against
# deploy/PRE-DEPLOY-CHECKLIST.md. Exit code is non-zero if any FAIL is emitted.
set -uo pipefail

fails=0
ok()   { printf '  PASS  %s\n' "$1"; }
warn() { printf '  WARN  %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; fails=$((fails+1)); }
sec()  { printf '\n== %s ==\n' "$1"; }

sec "Services"
for u in socrate socrate-admin-bff socrate-monitoring-bff caddy postgresql; do
  st="$(systemctl is-active "$u" 2>/dev/null || true)"
  [ "$st" = active ] && ok "$u active" || warn "$u: ${st:-unknown}"
done

sec "Listening ports (public 80/443 only; app + db loopback)"
ss -lntH 2>/dev/null | awk '{print $4}' | sort -u | while read -r addr; do
  port="${addr##*:}"
  case "$port" in
    80|443) echo "  ok    public :$port" ;;
    8080|8081|8090|8091|5432)
      case "$addr" in
        127.0.0.1:*|\[::1\]:*) echo "  ok    loopback :$port" ;;
        *) echo "  FAIL  :$port bound to $addr (must be loopback)" ;;
      esac ;;
  esac
done

sec "Env files (perms + key settings)"
for f in /etc/socrate/socrate.env /etc/socrate/admin-bff.env /etc/socrate/bff.env; do
  [ -f "$f" ] || { warn "$f missing"; continue; }
  echo "  $f -> $(stat -c '%a %U:%G' "$f")"
  case "$(stat -c '%a' "$f")" in 600|640) ;; *) warn "perms on $f (want 0640/0600)";; esac
done
E=/etc/socrate/socrate.env
if [ -f "$E" ]; then
  get() { grep -E "^$1=" "$E" | head -1 | cut -d= -f2- ; }
  [ "$(get ENV)" = production ] && ok "ENV=production" || warn "ENV=$(get ENV) (want production)"
  [ "$(get AUTO_MIGRATE)" = false ] && ok "AUTO_MIGRATE=false" || warn "AUTO_MIGRATE=$(get AUTO_MIGRATE) (true is for the one-time migrate only)"
  case "$(get OAUTH_ISSUER)" in https://*) ok "OAUTH_ISSUER=$(get OAUTH_ISSUER)";; *) bad "OAUTH_ISSUER not https: $(get OAUTH_ISSUER)";; esac
  case "$(get POLICY_MODE)" in off|shadow) ok "POLICY_MODE=$(get POLICY_MODE)";; *) warn "POLICY_MODE=$(get POLICY_MODE) (enforce = deliberate?)";; esac
  [ "$(get TRUSTED_PROXIES)" = "127.0.0.1/32,::1/128" ] && ok "TRUSTED_PROXIES loopback" || warn "TRUSTED_PROXIES=$(get TRUSTED_PROXIES)"
  v="$(get SECRET_KEY_BASE)"; [ "${#v}" -ge 32 ] && ok "SECRET_KEY_BASE >= 32 bytes" || bad "SECRET_KEY_BASE too short (${#v})"
fi

sec "Signing keys"
if [ -d /var/lib/socrate/keys ]; then
  echo "  $(stat -c '%a %U:%G' /var/lib/socrate/keys) /var/lib/socrate/keys"
  [ "$(stat -c '%a' /var/lib/socrate/keys)" = 700 ] && ok "keys dir 0700" || warn "keys dir perms (want 0700)"
  ls /var/lib/socrate/keys/*.pem >/dev/null 2>&1 && ok "keys present" || warn "no .pem keys in /var/lib/socrate/keys"
else
  bad "/var/lib/socrate/keys missing"
fi

sec "Caddy"
if command -v caddy >/dev/null 2>&1; then
  caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1 && ok "caddy validate" || bad "caddy validate failed"
fi
grep -q 'import /etc/caddy/sites' /etc/caddy/Caddyfile 2>/dev/null && ok "imports sites/*.caddy" || warn "main Caddyfile has no 'import /etc/caddy/sites/*.caddy'"
# The admin API (:8081) and /metrics must never appear in a public site block.
if grep -rqsE ':8081' /etc/caddy 2>/dev/null; then
  warn "':8081' appears under /etc/caddy — the admin API must NOT be publicly routed"
else
  ok "admin API (:8081) not referenced in Caddy config"
fi

sec "Health (loopback)"
for u in "http://127.0.0.1:8080/health/readiness" "http://127.0.0.1:8080/.well-known/openid-configuration"; do
  code="$(curl -s -o /dev/null -w '%{http_code}' "$u" 2>/dev/null)"
  [ "$code" = 200 ] && ok "$u -> 200" || bad "$u -> ${code:-no-response}"
done
ver="$(curl -s http://127.0.0.1:8081/metrics 2>/dev/null | grep -m1 socrate_build_info || true)"
echo "  build_info: ${ver:-<unavailable on :8081/metrics>}"
echo "$ver" | grep -q 'version="dev"' && warn "server reports version=dev (not built from a tag)"

sec "OS hygiene"
[ -f /var/run/reboot-required ] && warn "reboot required" || ok "no reboot flagged"
upd="$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst' || echo 0)"
[ "$upd" -gt 0 ] && warn "$upd package update(s) pending" || ok "packages up to date"

printf '\n== done: %s FAIL check(s). Review WARN/FAIL against deploy/PRE-DEPLOY-CHECKLIST.md ==\n' "$fails"
[ "$fails" -eq 0 ]
