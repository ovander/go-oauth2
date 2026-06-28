#!/usr/bin/env bash
# bootstrap.sh — one-time VPS prep for the Socrate backend (run as root). Idempotent.
# Creates the service user, the /etc/socrate + /var/lib/socrate layout, installs
# the systemd unit and the Caddy site, seeds the env file, and reminds you to
# generate signing keys.
#
# Paths here are the CANONICAL ones shared with the authoritative full-stack
# runbook in the oauth2-monitoring deploy kit (the umbrella guide). If you are
# deploying the whole VPS (Socrate + BFF + SPAs), follow that runbook instead;
# this script is the backend-only subset and uses the same paths so the two
# never conflict.
#
#   sudo bash bootstrap.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
deploy_dir="$(cd "$here/.." && pwd)"

echo "▶ creating service user 'socrate' (no login)…"
id -u socrate >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin socrate

echo "▶ creating layout (/etc/socrate, /var/lib/socrate)…"
install -d -o root    -g root    -m 0755 /etc/socrate
install -d -o socrate -g socrate -m 0750 /var/lib/socrate /var/lib/socrate/keys /var/lib/socrate/data

echo "▶ installing systemd unit…"
cp "$deploy_dir/systemd/socrate.service" /etc/systemd/system/
systemctl daemon-reload

echo "▶ seeding env file…"
if [ ! -f /etc/socrate/socrate.env ]; then
  cp "$deploy_dir/env/socrate.env.example" /etc/socrate/socrate.env
  chown root:socrate /etc/socrate/socrate.env
  chmod 0640 /etc/socrate/socrate.env
  echo "  · /etc/socrate/socrate.env created — EDIT IT (DATABASE_URL, SECRET_KEY_BASE, issuer)"
else
  echo "  · /etc/socrate/socrate.env exists — left untouched"
fi

echo "▶ installing Caddy site…"
if [ -d /etc/caddy ]; then
  cp "$deploy_dir/Caddyfile.example" /etc/caddy/socrate.Caddyfile
  echo "  · /etc/caddy/socrate.Caddyfile installed — import it from your main Caddyfile"
else
  echo "  ⚠ /etc/caddy not found — install Caddy first"
fi

cat <<'EOF'

Next:
  1. Edit /etc/socrate/socrate.env (secrets, DB URL, issuer).
  2. Postgres:  sudo -u postgres createuser socrate; sudo -u postgres createdb -O socrate socrate
  3. Signing keys (RSA):
       cd <repo> && make gen-keys
       sudo cp -r keys/. /var/lib/socrate/keys/
       sudo chown -R socrate:socrate /var/lib/socrate/keys && sudo chmod 0700 /var/lib/socrate/keys
     (KEYS_PATH in socrate.env must point at /var/lib/socrate/keys.)
  4. Migrate once:  set AUTO_MIGRATE=true in socrate.env, start the service, then set it back to false
                    (or run 'make migrate-up' if you manage goose migrations).
  5. Install the binary to /usr/local/bin/socrate. The production path is the
     umbrella push.sh (oauth2-monitoring/deploy/scripts/push.sh), which builds
     this repo and installs it with health-check + auto-rollback.
  6. Enable + start:  sudo systemctl enable --now socrate
  7. Reload Caddy:  sudo systemctl reload caddy
EOF
