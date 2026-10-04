#!/usr/bin/env bash
# socrate-release.sh - build a Socrate suite release on your workstation (macOS or Linux).
#
#   cd <folder holding your go-oauth2, oauth2-admin and oauth2-monitoring clones (or links)>
#   bash /path/to/go-oauth2/deploy/release-kit/socrate-release.sh v1.10.0 v1.5.0 v1.0.1
#
# The arguments are the Socrate, admin console and monitoring console tags. They must be
# annotated tags, present on origin; set ALLOW_UNTAGGED=1 for a dry build from any ref.
#
# Writes into ./release/ (or OUT_DIR), ready to upload:
#   socrate-suite-<socrate tag>.tar.gz   the bundle: static linux/amd64 binaries, both SPAs, the
#                                         systemd units, the admin Caddy headers and @bff paths, a
#                                         MANIFEST and a SHA256SUMS
#   socrate-vps-install.sh               installer / upgrader (copied from this kit)
#   socrate-caddy-update.sh              Caddy site updater (copied from this kit)
#   RUNBOOK-<socrate tag>.md             the deploy steps, filled with this build's values
#   SHA256-<socrate tag>.txt             checksums of the four files above
#
# Needs: git, Go (any version with GOTOOLCHAIN=auto: each build uses the Go its go.mod names,
# and the script checks it), Node.js >= each console's .nvmrc with npm, tar.
# Nothing is pushed or deployed. The clones are only read (and fetched when FETCH=1); the
# builds run in temporary worktrees, so your checkouts are left untouched.
#
# Portable on purpose: runs under macOS's bash 3.2 (no associative arrays, ASCII only) and
# uses shasum when sha256sum is missing. COPYFILE_DISABLE keeps macOS metadata (._ files) out
# of the archive.
set -euo pipefail
export COPYFILE_DISABLE=1

SOCRATE_REF="${1:-${SOCRATE_REF:-}}"; ADMIN_REF="${2:-${ADMIN_REF:-}}"; MON_REF="${3:-${MON_REF:-}}"
if [ -z "$SOCRATE_REF" ] || [ -z "$ADMIN_REF" ] || [ -z "$MON_REF" ]; then
  echo "usage: bash $0 <socrate tag> <admin tag> <monitoring tag>   (e.g. v1.10.0 v1.5.0 v1.0.1)" >&2
  exit 2
fi
KIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(pwd)"
OUT="${OUT_DIR:-$ROOT/release}"
GO_OAUTH2="$ROOT/go-oauth2"; ADMIN="$ROOT/oauth2-admin"; MON="$ROOT/oauth2-monitoring"
VPS_SSH="${VPS_SSH:-<user>@<vps>}"
PUBLIC_ISSUER="${PUBLIC_ISSUER:-https://socrate.vandermoten.eu}"

ok()   { printf '  [ok] %s\n' "$*"; }
info() { printf '  - %s\n' "$*"; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
step() { printf '\n==> %s\n' "$*"; }

if command -v sha256sum >/dev/null 2>&1; then SHA256="sha256sum"; else SHA256="shasum -a 256"; fi

# ---- 0. Preflight -------------------------------------------------------------------
step "preflight"
for d in "$GO_OAUTH2" "$ADMIN" "$MON"; do
  [ -d "$d/.git" ] || [ -f "$d/.git" ] || git -C "$d" rev-parse --git-dir >/dev/null 2>&1 \
    || die "$d is not a git clone: run from the folder holding go-oauth2, oauth2-admin and oauth2-monitoring"
done
for c in git go node npm tar; do command -v "$c" >/dev/null 2>&1 || die "missing command: $c"; done
for f in socrate-vps-install.sh socrate-caddy-update.sh; do [ -f "$KIT_DIR/$f" ] || die "$KIT_DIR/$f missing"; done

if [ "${FETCH:-0}" = 1 ]; then
  for d in "$GO_OAUTH2" "$ADMIN" "$MON"; do git -C "$d" fetch --quiet --tags origin; done
  ok "fetched tags"
fi

# check_ref REPO REF: the ref exists; unless ALLOW_UNTAGGED=1 it is an annotated tag whose
# object is the same on origin (so the bundle is built from what was published).
check_ref() {
  local repo="$1" ref="$2" remote
  git -C "$repo" rev-parse --verify --quiet "${ref}^{commit}" >/dev/null \
    || die "$ref not found in $repo (fetch the tags first: git -C $repo fetch --tags origin)"
  [ "${ALLOW_UNTAGGED:-0}" = 1 ] && return 0
  [ "$(git -C "$repo" cat-file -t "$ref" 2>/dev/null)" = tag ] || die "$ref in $repo is not an annotated tag"
  remote="$(git -C "$repo" ls-remote --tags origin "refs/tags/$ref" | awk '{print $1}')"
  [ -n "$remote" ] || die "$ref is not on origin for $repo (push it first)"
  [ "$remote" = "$(git -C "$repo" rev-parse "$ref")" ] || die "$ref differs between $repo and its origin"
}
check_ref "$GO_OAUTH2" "$SOCRATE_REF"; check_ref "$ADMIN" "$ADMIN_REF"; check_ref "$MON" "$MON_REF"
SOC_COMMIT="$(git -C "$GO_OAUTH2" rev-parse "${SOCRATE_REF}^{commit}")"
ADMIN_COMMIT="$(git -C "$ADMIN" rev-parse "${ADMIN_REF}^{commit}")"
MON_COMMIT="$(git -C "$MON" rev-parse "${MON_REF}^{commit}")"
ok "go-oauth2 ${SOCRATE_REF} ${SOC_COMMIT}"
ok "oauth2-admin ${ADMIN_REF} ${ADMIN_COMMIT}"
ok "oauth2-monitoring ${MON_REF} ${MON_COMMIT}"

node_major="$(node -v | sed -E 's/^v([0-9]+).*/\1/')"

# ---- worktrees ----------------------------------------------------------------------
WORK="$(mktemp -d)"
WTS=""
cleanup() {
  for pair in $WTS; do
    git -C "${pair%%::*}" worktree remove --force "${pair##*::}" >/dev/null 2>&1 || true
  done
  rm -rf "$WORK"
  for d in "$GO_OAUTH2" "$ADMIN" "$MON"; do git -C "$d" worktree prune >/dev/null 2>&1 || true; done
}
trap cleanup EXIT
# worktree REPO REF PATH. Called directly, not in $(...), so WTS reaches the cleanup trap.
worktree() {
  WTS="$WTS $1::$3"
  git -C "$1" worktree add --quiet --detach "$3" "$2"
}
SOC_SRC="$WORK/go-oauth2"; ADMIN_SRC="$WORK/oauth2-admin"; MON_SRC="$WORK/oauth2-monitoring"
worktree "$GO_OAUTH2" "$SOCRATE_REF" "$SOC_SRC"
worktree "$ADMIN" "$ADMIN_REF" "$ADMIN_SRC"
worktree "$MON" "$MON_REF" "$MON_SRC"

for src in "$ADMIN_SRC" "$MON_SRC"; do
  want="$(tr -dc '0-9.' < "$src/.nvmrc" 2>/dev/null | cut -d. -f1)"
  [ -z "$want" ] || [ "$node_major" -ge "$want" ] || die "Node $(node -v) is older than $(basename "$src")'s .nvmrc ($want)"
done

BUNDLE_NAME="socrate-suite-${SOCRATE_REF}"
B="$WORK/$BUNDLE_NAME"
mkdir -p "$B/bin" "$B/www/admin" "$B/www/monitoring" "$B/systemd" "$B/caddy"
BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# go_want SRC -> the Go the module names (toolchain line, else go line), e.g. go1.27.1
go_want() { awk '/^toolchain /{t=$2} /^go /{g="go"$2} END{print (t != "" ? t : g)}' "$1/go.mod"; }
# go_check BINARY SRC: the binary was built with the Go its go.mod names.
go_check() {
  local got want; got="$(go version "$1" | awk '{print $2}')"; want="$(go_want "$2")"
  [ "$got" = "$want" ] || die "$(basename "$1") built with $got, but $2/go.mod names $want"
}
gobuild() { # SRC_DIR OUTPUT PACKAGE LDFLAGS
  (cd "$1" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$4" -o "$2" "$3")
}

# ---- 1. Socrate server + seed -------------------------------------------------------
step "Socrate ${SOCRATE_REF}"
mod="$(awk '/^module /{print $2; exit}' "$SOC_SRC/go.mod")"
branch="detached"
if git -C "$GO_OAUTH2" merge-base --is-ancestor "$SOC_COMMIT" origin/main 2>/dev/null; then branch="main"; fi
vflags="-s -w -X ${mod}/internal/version.Version=${SOCRATE_REF} -X ${mod}/internal/version.Commit=${SOC_COMMIT:0:7} -X ${mod}/internal/version.BuildTime=${BUILD_TIME} -X ${mod}/internal/version.Branch=${branch}"
gobuild "$SOC_SRC" "$B/bin/socrate" ./cmd/server "$vflags"
gobuild "$SOC_SRC" "$B/bin/socrate-seed" ./cmd/seed "$vflags"
# -X silently ignores a symbol that does not exist; the build time is unique to this run, so
# finding it in the binary proves the version stamp landed.
grep -aqF -- "$BUILD_TIME" "$B/bin/socrate" || die "version stamp missing from bin/socrate (${mod}/internal/version)"
go_check "$B/bin/socrate" "$SOC_SRC"
ok "bin/socrate, bin/socrate-seed (version ${SOCRATE_REF}, commit ${SOC_COMMIT:0:7}, $(go_want "$SOC_SRC"))"

# ---- 2. Admin console ---------------------------------------------------------------
step "admin console ${ADMIN_REF}"
gobuild "$ADMIN_SRC/bff" "$B/bin/socrate-admin-bff" . "-s -w"
go_check "$B/bin/socrate-admin-bff" "$ADMIN_SRC/bff"
(cd "$ADMIN_SRC" && npm ci --no-audit --no-fund --loglevel=error && npm run build --silent) >"$WORK/admin-npm.log" 2>&1 \
  || { tail -30 "$WORK/admin-npm.log" >&2; die "admin SPA build failed"; }
cp -R "$ADMIN_SRC/dist" "$B/www/admin/dist"
ok "bin/socrate-admin-bff, www/admin/dist"

# ---- 3. Monitoring console ----------------------------------------------------------
step "monitoring console ${MON_REF}"
gobuild "$MON_SRC/bff" "$B/bin/socrate-monitoring-bff" . "-s -w"
go_check "$B/bin/socrate-monitoring-bff" "$MON_SRC/bff"
(cd "$MON_SRC" && npm ci --no-audit --no-fund --loglevel=error && npm run build --silent) >"$WORK/mon-npm.log" 2>&1 \
  || { tail -30 "$WORK/mon-npm.log" >&2; die "monitoring SPA build failed"; }
cp -R "$MON_SRC/dist" "$B/www/monitoring/dist"
ok "bin/socrate-monitoring-bff, www/monitoring/dist"

# ---- 4. systemd units and admin Caddy headers ---------------------------------------
step "units and Caddy headers"
cp "$SOC_SRC/deploy/systemd/socrate.service" "$B/systemd/"
cp "$ADMIN_SRC/deploy/systemd/socrate-admin-bff.service" "$B/systemd/"
cp "$MON_SRC/deploy/systemd/socrate-monitoring-bff.service" "$B/systemd/"
# oauth2-monitoring mirrors socrate.service for its bootstrap; the headers differ by design.
if [ -f "$MON_SRC/deploy/systemd/socrate.service" ] \
  && [ "$(grep -v '^#' "$MON_SRC/deploy/systemd/socrate.service")" != "$(grep -v '^#' "$SOC_SRC/deploy/systemd/socrate.service")" ]; then
  info "note: oauth2-monitoring's mirror of socrate.service differs from go-oauth2's; the bundle ships go-oauth2's (canonical)"
fi
caddyfile="$ADMIN_SRC/deploy/Caddyfile"
csp="$(sed -nE 's/^[[:space:]]*Content-Security-Policy[[:space:]]+"([^"]*)".*/\1/p' "$caddyfile")"
ro="$(sed -nE 's/^[[:space:]]*Content-Security-Policy-Report-Only[[:space:]]+"([^"]*)".*/\1/p' "$caddyfile")"
rep="$(sed -nE 's/^[[:space:]]*Reporting-Endpoints[[:space:]]+`([^`]*)`.*/\1/p' "$caddyfile")"
bff="$(sed -nE 's/^[[:space:]]*@bff[[:space:]]+path[[:space:]]+(.*)$/\1/p' "$caddyfile")"
[ "$(printf '%s\n' "$csp" | grep -c .)" = 1 ] || die "expected one Content-Security-Policy line in $caddyfile"
case "$csp" in *"default-src 'none'"*"object-src 'none'"*) ;; *) die "admin CSP looks wrong: $csp";; esac
[ -n "$bff" ] || die "no '@bff path' line in $caddyfile"
printf '%s\n' "$csp" > "$B/caddy/admin-csp.txt"
if [ -n "$ro" ] || [ -n "$rep" ]; then
  [ -n "$ro" ] && [ -n "$rep" ] || die "$caddyfile has only one of Report-Only / Reporting-Endpoints"
  printf '%s\n' "$ro" > "$B/caddy/admin-csp-report-only.txt"
  printf '%s\n' "$rep" > "$B/caddy/admin-reporting-endpoints.txt"
fi
printf '%s\n' "$bff" > "$B/caddy/admin-bff-paths.txt"
ok "systemd/*.service, caddy/admin-csp*.txt, caddy/admin-bff-paths.txt"

# ---- 5. MANIFEST, SHA256SUMS, archive -----------------------------------------------
step "bundle"
cat > "$B/MANIFEST" <<EOF
Socrate suite release bundle - built ${BUILD_TIME}, linux/amd64, CGO disabled (static)
socrate, socrate-seed        github.com/ovander/go-oauth2       ${SOCRATE_REF}  commit ${SOC_COMMIT}
socrate-admin-bff, www/admin github.com/ovander/oauth2-admin    ${ADMIN_REF}  commit ${ADMIN_COMMIT}
socrate-monitoring-bff, www/monitoring  github.com/ovander/oauth2-monitoring  ${MON_REF}  commit ${MON_COMMIT}
systemd/*.service            canonical units from each repo at its ref
caddy/admin-csp.txt          admin CSP from oauth2-admin ${ADMIN_REF} deploy/Caddyfile (== productionCsp())
caddy/admin-csp-report-only.txt, admin-reporting-endpoints.txt  Report-Only policy + Reporting-Endpoints from the same Caddyfile
caddy/admin-bff-paths.txt    the admin site's @bff paths from the same Caddyfile
Go $(go_want "$SOC_SRC")   Node $(node -v)
EOF
(cd "$B" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort | while IFS= read -r f; do $SHA256 "$f"; done > SHA256SUMS)
(cd "$B" && $SHA256 -c --quiet SHA256SUMS >/dev/null 2>&1 || $SHA256 -c SHA256SUMS >/dev/null) || die "SHA256SUMS does not verify"
mkdir -p "$OUT"
tar -czf "$OUT/${BUNDLE_NAME}.tar.gz" -C "$WORK" "$BUNDLE_NAME"
if tar -tzf "$OUT/${BUNDLE_NAME}.tar.gz" | grep -q '/\._'; then die "the archive contains macOS ._ files"; fi
cp "$KIT_DIR/socrate-vps-install.sh" "$KIT_DIR/socrate-caddy-update.sh" "$OUT/"
bundle_sha="$($SHA256 "$OUT/${BUNDLE_NAME}.tar.gz" | awk '{print $1}')"
ok "$OUT/${BUNDLE_NAME}.tar.gz"

# ---- 6. Runbook and checksums -------------------------------------------------------
fence='```'
cat > "$OUT/RUNBOOK-${SOCRATE_REF}.md" <<EOF
# Deploy Socrate ${SOCRATE_REF}

Bundle: \`${BUNDLE_NAME}.tar.gz\`, sha256 \`${bundle_sha}\`
Socrate ${SOCRATE_REF} (${SOC_COMMIT:0:7}), admin console ${ADMIN_REF} (${ADMIN_COMMIT:0:7}), monitoring console ${MON_REF} (${MON_COMMIT:0:7}), built ${BUILD_TIME}.

## 1. Upload (workstation)

${fence}
cd ${OUT}
rsync -P -e "ssh -o IPQoS=none -o ServerAliveInterval=15" ${BUNDLE_NAME}.tar.gz socrate-vps-install.sh socrate-caddy-update.sh ${VPS_SSH}:
ssh -t ${VPS_SSH}
${fence}

## 2. Back up, verify, unpack, install (VPS)

${fence}
cd ~
sudo /usr/local/sbin/socrate-backup.sh | tail -1
echo "${bundle_sha}  ${BUNDLE_NAME}.tar.gz" | sha256sum -c - && tar -xzf ${BUNDLE_NAME}.tar.gz && (cd ${BUNDLE_NAME} && sha256sum --quiet -c SHA256SUMS && echo CHECKSUMS-OK)
sudo bash socrate-vps-install.sh ./${BUNDLE_NAME}
${fence}

Expect \`CHECKSUMS-OK\`, the backed-up server's version, the number of schema migrations applied,
and \`all smoke tests passed\`.

## 3. Caddy sites (VPS)

${fence}
sudo bash socrate-caddy-update.sh ./${BUNDLE_NAME}
sudo bash socrate-caddy-update.sh ./${BUNDLE_NAME} --apply
${fence}

The first run only shows the plan; \`--apply\` backs up, edits, validates and reloads. \`Nothing to do.\`
means the sites are already in line.

## 4. Check (workstation)

${fence}
curl -s ${PUBLIC_ISSUER}/version; echo
${fence}

Expect \`"version":"${SOCRATE_REF}"\` and \`"commit":"${SOC_COMMIT:0:7}"\`.
EOF
(cd "$OUT" && $SHA256 "${BUNDLE_NAME}.tar.gz" socrate-vps-install.sh socrate-caddy-update.sh "RUNBOOK-${SOCRATE_REF}.md" > "SHA256-${SOCRATE_REF}.txt")
ok "runbook: $OUT/RUNBOOK-${SOCRATE_REF}.md"

printf '\nReady in %s:\n' "$OUT"
sed 's/^/  /' "$OUT/SHA256-${SOCRATE_REF}.txt"
