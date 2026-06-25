#!/usr/bin/env bash
# bootstrap.sh — one-time VPS prep for the Socrate backend (run as root). Idempotent.
# Creates the service user + /opt/socrate layout, installs the systemd unit and the
# Caddy site, seeds the env file, and reminds you to generate signing keys.
#
#   sudo bash bootstrap.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
deploy_dir="$(cd "$here/.." && pwd)"
root="/opt/socrate"

echo "▶ creating service user 'socrate' (no login)…"
id -u socrate >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin socrate

echo "▶ creating $root layout…"
install -d -o socrate -g socrate "$root" "$root/bin" "$root/keys" "$root/data"

echo "▶ installing systemd unit…"
cp "$deploy_dir/systemd/socrate.service" /etc/systemd/system/
systemctl daemon-reload

echo "▶ seeding env file…"
if [ ! -f "$root/.env" ]; then
  cp "$deploy_dir/env/socrate.env.example" "$root/.env"
  chown root:socrate "$root/.env"
  chmod 0640 "$root/.env"
  echo "  · $root/.env created — EDIT IT (DATABASE_URL, SECRET_KEY_BASE, issuer)"
else
  echo "  · $root/.env exists — left untouched"
fi

echo "▶ installing Caddy site…"
if [ -d /etc/caddy ]; then
  cp "$deploy_dir/Caddyfile.example" /etc/caddy/socrate.Caddyfile
  echo "  · /etc/caddy/socrate.Caddyfile installed — import it from your main Caddyfile"
else
  echo "  ⚠ /etc/caddy not found — install Caddy first"
fi

cat <<EOF

Next:
  1. Edit $root/.env (secrets, DB URL, issuer).
  2. Postgres:  sudo -u postgres createuser socrate; sudo -u postgres createdb -O socrate socrate
  3. Signing keys (RSA):  cd <repo> && make gen-keys && sudo cp -r keys/. $root/keys/ && sudo chown -R socrate:socrate $root/keys
  4. Migrate once:  set AUTO_MIGRATE=true in $root/.env, start the service, then set it back to false
                    (or use 'make migrate-up' if you manage goose migrations).
  5. Deploy the binary:  make deploy VPS=<user@host>   (builds linux, scp → $root/bin/oauth-server, restarts)
  6. Enable + start:  sudo systemctl enable --now socrate
  7. Reload Caddy:  sudo systemctl reload caddy
EOF
