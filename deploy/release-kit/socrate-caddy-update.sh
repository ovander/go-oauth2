#!/usr/bin/env bash
# socrate-caddy-update.sh — bring the live console Caddy sites in line with the suite bundle.
# Run as root on the VPS, AFTER the new BFFs are installed (socrate-vps-install.sh):
#
#   sudo bash socrate-caddy-update.sh ./socrate-suite-vX.Y.Z            # dry run: show the plan
#   sudo bash socrate-caddy-update.sh ./socrate-suite-vX.Y.Z --apply    # back up, edit, validate, reload
#
# Edits, all idempotent (one already in place is reported and skipped):
#   1. monitor site: /api/version in the @bff matcher (monitoring v1.0.0+ routes it).
#   2. admin site: Content-Security-Policy = the canonical policy in the bundle
#      (caddy/admin-csp.txt, == productionCsp() in oauth2-admin's src/security/csp.ts).
#   3. admin site, when the bundle carries them (admin v1.1.0+): Reporting-Endpoints and
#      Content-Security-Policy-Report-Only (the Trusted Types policy, reporting to the admin
#      BFF's POST /bff/csp-report), from caddy/admin-reporting-endpoints.txt and
#      caddy/admin-csp-report-only.txt — inserted after the CSP line, in the same form, or
#      updated in place if already there.
#   4. admin site, when the bundle carries caddy/admin-bff-paths.txt: every path the admin
#      console's deploy/Caddyfile routes to the BFF is in the site's @bff matcher (admin v1.5.0
#      adds /api/profile/mfa and /api/profile/mfa/*). Missing paths are appended; none is removed.
# Nothing else in the site files changes. The legacy site and the main Caddyfile are not touched.
# On a validation or reload failure the originals are restored.
set -euo pipefail

BUNDLE="${1:?usage: $0 <bundle-dir> [--apply]}"
APPLY=0; [ "${2:-}" = "--apply" ] && APPLY=1
SITES="${SITES:-/etc/caddy/sites}"
ADMIN_HOST="${ADMIN_HOST:-admin.socrate.vandermoten.eu}"
MON_HOST="${MON_HOST:-monitor.socrate.vandermoten.eu}"
ADMIN_SITE="$SITES/$ADMIN_HOST.caddy"
MON_SITE="$SITES/$MON_HOST.caddy"
CADDYFILE="${CADDYFILE:-/etc/caddy/Caddyfile}"
BACKUP="${BACKUP_ROOT:-/var/backups/socrate}/caddy-$(date +%Y%m%d-%H%M%S)"

ok()   { printf '  \033[32m✔\033[0m %s\n' "$*"; }
info() { printf '  · %s\n' "$*"; }
warn() { printf '  \033[33m⚠\033[0m %s\n' "$*"; }
die()  { printf '\033[31m✖ %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root"
[ -f "$BUNDLE/caddy/admin-csp.txt" ] || die "$BUNDLE/caddy/admin-csp.txt not found — pass the unpacked bundle directory"
for f in "$ADMIN_SITE" "$MON_SITE" "$CADDYFILE"; do [ -f "$f" ] || die "$f not found"; done
command -v caddy >/dev/null || die "caddy not found"
CSP="$(tr -d '\n' < "$BUNDLE/caddy/admin-csp.txt")"
case "$CSP" in *"default-src 'none'"*"object-src 'none'"*) ;; *) die "admin-csp.txt does not look like the canonical policy: $CSP";; esac

RO=""; RE=""
if [ -f "$BUNDLE/caddy/admin-csp-report-only.txt" ] || [ -f "$BUNDLE/caddy/admin-reporting-endpoints.txt" ]; then
  [ -s "$BUNDLE/caddy/admin-csp-report-only.txt" ] && [ -s "$BUNDLE/caddy/admin-reporting-endpoints.txt" ] \
    || die "the bundle has only one of admin-csp-report-only.txt / admin-reporting-endpoints.txt"
  RO="$(tr -d '\n' < "$BUNDLE/caddy/admin-csp-report-only.txt")"
  RE="$(tr -d '\n' < "$BUNDLE/caddy/admin-reporting-endpoints.txt")"
  case "$RO" in *"require-trusted-types-for 'script'"*"report-uri /bff/csp-report"*) ;; *) die "admin-csp-report-only.txt looks wrong: $RO";; esac
  [ "$RE" = 'csp="/bff/csp-report"' ] || die "admin-reporting-endpoints.txt looks wrong: $RE"
fi

BFF_PATHS=""
if [ -f "$BUNDLE/caddy/admin-bff-paths.txt" ]; then
  BFF_PATHS="$(tr '\n' ' ' < "$BUNDLE/caddy/admin-bff-paths.txt")"
  # One check per path: a single pattern with two space-delimited literals would need two
  # spaces between adjacent paths, and refused every real file.
  for p in '/bff/*' '/api/admin/*'; do
    case " $BFF_PATHS " in *" $p "*) ;; *) die "admin-bff-paths.txt looks wrong (no $p): $BFF_PATHS";; esac
  done
fi

# Compute the new contents into temp files (no change on disk yet).
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
python3 - "$MON_SITE" "$tmp/mon" <<'MONPY'
import re, sys
s = open(sys.argv[1]).read()
lines = [l for l in s.splitlines(True) if re.match(r'\s*@bff path ', l)]
if len(lines) != 1: sys.exit(f"expected one '@bff path' line in {sys.argv[1]}, found {len(lines)}")
l = lines[0]
if '/api/version' not in l.split():
    s = s.replace(l, l.rstrip('\n') + ' /api/version\n', 1)
open(sys.argv[2], 'w').write(s)
MONPY
python3 - "$ADMIN_SITE" "$tmp/admin" "$CSP" "$RO" "$RE" "$BFF_PATHS" "$tmp/bff-added" <<'ADMINPY'
import re, sys
site, out, csp, ro, rep, bff_paths, added_out = sys.argv[1:8]
s = open(site).read()

# The enforced policy: exactly one line, "Content-Security-Policy" followed by whitespace (so the
# Report-Only header does not match), bare inside a header block or as "header Name value".
pat = re.compile(r'^([ \t]*(?:header[ \t]+)?)Content-Security-Policy([ \t]+)"[^"\n]*"[^\n]*\n', re.M)
hits = pat.findall(s)
if len(hits) != 1: sys.exit(f"expected one Content-Security-Policy line in {site}, found {len(hits)}")
m = pat.search(s)
lead, gap = m.group(1), m.group(2)
s = s[:m.start()] + f'{lead}Content-Security-Policy{gap}"{csp}"\n' + s[m.end():]

def upsert(s, after, name, value):
    """Replace the one `name` line, or insert it at offset `after`; return (s, end of the line)."""
    p = re.compile(r'^[ \t]*(?:header[ \t]+)?' + re.escape(name) + r'[ \t]+[^\n]*\n', re.M)
    found = list(p.finditer(s))
    if len(found) > 1: sys.exit(f"expected at most one {name} line in {site}, found {len(found)}")
    line = f'{lead}{name}{gap}{value}\n'
    if found:
        f = found[0]
        return s[:f.start()] + line + s[f.end():], f.start() + len(line)
    return s[:after] + line + s[after:], after + len(line)

if ro:
    end = pat.search(s).end()
    s, end = upsert(s, end, 'Reporting-Endpoints', '`' + rep + '`')
    s, end = upsert(s, end, 'Content-Security-Policy-Report-Only', '"' + ro + '"')

if bff_paths.split():
    lines = [l for l in s.splitlines(True) if re.match(r'\s*@bff path ', l)]
    if len(lines) != 1: sys.exit(f"expected one '@bff path' line in {site}, found {len(lines)}")
    l = lines[0]
    have = l.split()
    missing = [p for p in bff_paths.split() if p not in have]
    if missing:
        s = s.replace(l, l.rstrip('\n') + ' ' + ' '.join(missing) + '\n', 1)
        open(added_out, 'w').write(' '.join(missing) + '\n')
open(out, 'w').write(s)
ADMINPY

changed=0
printf '\n\033[1m▶ plan\033[0m\n'
if cmp -s "$MON_SITE" "$tmp/mon"; then ok "monitor: @bff already routes /api/version"; else
  changed=1; info "monitor ($MON_SITE):"; { diff -u "$MON_SITE" "$tmp/mon" | sed -n '3,$p' | grep '^[-+]' | sed 's/^/      /'; } || true; fi
if cmp -s "$ADMIN_SITE" "$tmp/admin"; then ok "admin: CSP canonical${RO:+, Report-Only and Reporting-Endpoints in place}${BFF_PATHS:+, @bff routes every console path}"; else
  changed=1; info "admin ($ADMIN_SITE):"; { diff -u "$ADMIN_SITE" "$tmp/admin" | sed -n '3,$p' | grep '^[-+]' | cut -c1-160 | sed 's/^/      /'; } || true
  # The diff lines are cut for the long CSP values; name the added paths in full.
  [ -s "$tmp/bff-added" ] && info "admin @bff matcher: adding $(cat "$tmp/bff-added")"; fi
grep -q 'includeSubDomains"' "$ADMIN_SITE" && info "not changed: admin HSTS has no 'preload' (the repo's has) — add it only if you intend to submit the domain to the HSTS preload list"
[ "$changed" = 1 ] || { printf '\nNothing to do.\n'; exit 0; }
[ "$APPLY" = 1 ] || { printf '\nDry run only. Re-run with --apply.\n'; exit 0; }

printf '\n\033[1m▶ apply\033[0m\n'
install -d -m 0700 "$BACKUP"
cp -a "$MON_SITE" "$ADMIN_SITE" "$BACKUP/"
ok "backup in $BACKUP"
restore() { cp -a "$BACKUP/$(basename "$MON_SITE")" "$MON_SITE"; cp -a "$BACKUP/$(basename "$ADMIN_SITE")" "$ADMIN_SITE"; }
cat "$tmp/mon" > "$MON_SITE"; cat "$tmp/admin" > "$ADMIN_SITE"
if ! caddy validate --config "$CADDYFILE" --adapter caddyfile >"$tmp/validate.log" 2>&1; then
  restore; tail -5 "$tmp/validate.log" >&2; die "caddy validate failed — originals restored, Caddy not reloaded"
fi
ok "caddy validate: OK"
if ! systemctl reload caddy || ! systemctl is-active --quiet caddy; then
  restore; systemctl reload caddy || true; die "Caddy reload failed — originals restored"
fi
ok "Caddy reloaded"

printf '\n\033[1m▶ verify\033[0m\n'
sleep 1
hdrs="$(curl -sS --noproxy '*' -o /dev/null -D - --max-time 10 --resolve "$ADMIN_HOST:443:127.0.0.1" "https://$ADMIN_HOST/" | tr -d '\r' || true)"
hdr() { awk -F': ' -v n="$1" 'tolower($1)==n{sub(/^[^:]*: /,""); print; exit}' <<<"$hdrs"; }
got="$(hdr content-security-policy)"
[ "$got" = "$CSP" ] && ok "admin serves the canonical CSP" || warn "admin CSP header is '${got:-<none>}' — check from your browser"
if [ -n "$RO" ]; then
  got="$(hdr content-security-policy-report-only)"
  [ "$got" = "$RO" ] && ok "admin serves the Trusted Types Report-Only policy" || warn "admin Report-Only header is '${got:-<none>}'"
  got="$(hdr reporting-endpoints)"
  [ "$got" = "$RE" ] && ok "admin serves Reporting-Endpoints: $got" || warn "admin Reporting-Endpoints header is '${got:-<none>}'"
  # A non-report content type gets 415 from the BFF and is not logged; the SPA fallback never answers 415.
  code="$(curl -sS --noproxy '*' -o /dev/null -w '%{http_code}' --max-time 10 --resolve "$ADMIN_HOST:443:127.0.0.1" \
    -X POST -H 'Content-Type: text/plain' --data x "https://$ADMIN_HOST/bff/csp-report" || true)"
  [ "$code" = 415 ] && ok "POST /bff/csp-report reaches the admin BFF (415 for a non-report body)" \
    || warn "POST /bff/csp-report answered '$code' (want 415) — is admin BFF v1.1.0 installed?"
fi
case " $BFF_PATHS " in *" /api/profile/mfa "*)
  # Anonymous: the BFF answers 401; the SPA fallback would answer 200 with index.html.
  code="$(curl -sS --noproxy '*' -o /dev/null -w '%{http_code}' --max-time 10 --resolve "$ADMIN_HOST:443:127.0.0.1" "https://$ADMIN_HOST/api/profile/mfa" || true)"
  [ "$code" = 401 ] && ok "GET /api/profile/mfa reaches the admin BFF (401 without a session)" \
    || warn "GET /api/profile/mfa answered '$code' (want 401) — check the admin @bff matcher";;
esac
body="$(curl -sS --noproxy '*' --max-time 10 --resolve "$MON_HOST:443:127.0.0.1" "https://$MON_HOST/api/version" || true)"
case "$body" in \{*\"version\"*) ok "monitor /api/version → $body";;
  *'<!doctype'*|*'<!DOCTYPE'*) warn "monitor /api/version returns the SPA — is the monitoring BFF v1.0.0+ installed?";;
  *) warn "monitor /api/version answered '${body:0:80}'";; esac
printf '\nTo undo: cp %s/*.caddy %s/ && systemctl reload caddy\n' "$BACKUP" "$SITES"
