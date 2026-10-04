#!/usr/bin/env bash
# test-caddy-update.sh - run socrate-caddy-update.sh end to end (dry run and --apply) against
# fixture Caddy sites and a fixture bundle, with stub caddy, systemctl and curl commands. Needs root (the updater checks
# it): run as root, or with passwordless sudo, as on CI runners.
#
#   bash deploy/release-kit/test-caddy-update.sh
set -euo pipefail

KIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
SUDO=""; [ "$(id -u)" = 0 ] || SUDO="sudo"
fails=0
pass() { printf '  [ok] %s\n' "$*"; }
fail() { printf '  [FAIL] %s\n' "$*"; fails=$((fails + 1)); }

CSP="default-src 'none'; script-src 'self'; object-src 'none'"
RO="default-src 'none'; require-trusted-types-for 'script'; trusted-types vue default; report-uri /bff/csp-report; report-to csp"
RE='csp="/bff/csp-report"'
PATHS='/bff/* /api/admin/* /api/apps/* /api/profile /api/profile/mfa /api/profile/mfa/* /api/version /api/auth/request-password-reset /api/auth/reset-password'

mkdir -p "$T/bundle/caddy" "$T/sites" "$T/stub"
printf '%s\n' "$CSP" > "$T/bundle/caddy/admin-csp.txt"
printf '%s\n' "$RO" > "$T/bundle/caddy/admin-csp-report-only.txt"
printf '%s\n' "$RE" > "$T/bundle/caddy/admin-reporting-endpoints.txt"
printf '%s\n' "$PATHS" > "$T/bundle/caddy/admin-bff-paths.txt"
# caddy validate and systemctl reload / is-active succeed; curl (the post-reload checks)
# answers nothing, so those checks only warn.
for c in caddy systemctl; do printf '#!/bin/sh\nexit 0\n' > "$T/stub/$c"; chmod +x "$T/stub/$c"; done
printf '#!/bin/sh\nexit 7\n' > "$T/stub/curl"; chmod +x "$T/stub/curl"
: > "$T/Caddyfile"

# admin_site BFF_PATHS: an admin site already in line except, possibly, its @bff matcher.
admin_site() {
  cat > "$T/sites/admin.example.caddy" <<EOF
admin.example {
	header {
		Content-Security-Policy "$CSP"
		Reporting-Endpoints \`$RE\`
		Content-Security-Policy-Report-Only "$RO"
	}
	@bff path $1
	handle @bff {
		reverse_proxy 127.0.0.1:8092
	}
}
EOF
}
cat > "$T/sites/monitor.example.caddy" <<'EOF'
monitor.example {
	@bff path /bff/* /api/admin/* /api/version
	handle @bff {
		reverse_proxy 127.0.0.1:8090
	}
}
EOF

run() { # [--apply] -> output in $T/out, exit code in $rc
  rc=0
  $SUDO env PATH="$T/stub:$PATH" SITES="$T/sites" ADMIN_HOST=admin.example MON_HOST=monitor.example \
    CADDYFILE="$T/Caddyfile" BACKUP_ROOT="$T/backups" \
    bash "$KIT_DIR/socrate-caddy-update.sh" "$T/bundle" "$@" > "$T/out" 2>&1 || rc=$?
}

echo "socrate-caddy-update.sh:"

# 1. Production before admin v1.5.0: the MFA paths are missing and are planned, nothing written.
admin_site '/bff/* /api/admin/* /api/apps/* /api/profile /api/version /api/auth/request-password-reset /api/auth/reset-password'
before="$(cat "$T/sites/admin.example.caddy")"
run
if [ "$rc" = 0 ] && grep -qF 'admin @bff matcher: adding /api/profile/mfa /api/profile/mfa/*' "$T/out" && grep -q 'Dry run only' "$T/out"; then
  pass "missing @bff paths are planned"
else
  fail "missing @bff paths: rc=$rc"; sed 's/^/      /' "$T/out"
fi
[ "$before" = "$(cat "$T/sites/admin.example.caddy")" ] && pass "dry run leaves the site unchanged" || fail "dry run changed the site"

# 2. Sites already in line: nothing to do.
admin_site "$PATHS"
run
if [ "$rc" = 0 ] && grep -q 'Nothing to do' "$T/out"; then pass "sites in line: nothing to do"; else
  fail "sites in line: rc=$rc"; sed 's/^/      /' "$T/out"; fi

# 3. A malformed paths file is refused.
printf '/api/profile\n' > "$T/bundle/caddy/admin-bff-paths.txt"
run
if [ "$rc" != 0 ] && grep -q 'admin-bff-paths.txt looks wrong' "$T/out"; then pass "malformed admin-bff-paths.txt refused"; else
  fail "malformed paths file: rc=$rc"; sed 's/^/      /' "$T/out"; fi
printf '%s\n' "$PATHS" > "$T/bundle/caddy/admin-bff-paths.txt"

# 4. Two @bff lines in the admin site are refused rather than guessed.
admin_site "$PATHS"
printf '@bff path /other\n' >> "$T/sites/admin.example.caddy"
run
if [ "$rc" != 0 ] && grep -q "expected one '@bff path' line" "$T/out"; then pass "ambiguous @bff matcher refused"; else
  fail "two @bff lines: rc=$rc"; sed 's/^/      /' "$T/out"; fi

# 5. --apply writes the planned change, keeps a backup, and a second run has nothing to do.
admin_site '/bff/* /api/admin/* /api/profile /api/version'
run --apply
if [ "$rc" = 0 ] && grep -qF '@bff path /bff/* /api/admin/* /api/profile /api/version /api/apps/* /api/profile/mfa /api/profile/mfa/* /api/auth/request-password-reset /api/auth/reset-password' "$T/sites/admin.example.caddy" \
  && ls "$T"/backups/caddy-*/admin.example.caddy >/dev/null 2>&1; then
  pass "--apply appends the missing paths and keeps a backup"
else
  fail "--apply: rc=$rc"; sed 's/^/      /' "$T/out"; sed 's/^/      /' "$T/sites/admin.example.caddy"
fi
run
if [ "$rc" = 0 ] && grep -q 'Nothing to do' "$T/out"; then pass "after --apply: nothing to do"; else
  fail "after --apply: rc=$rc"; sed 's/^/      /' "$T/out"; fi

[ "$fails" = 0 ] || { echo "$fails failure(s)"; exit 1; }
echo "all passed"
