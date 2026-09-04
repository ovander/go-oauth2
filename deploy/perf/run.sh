#!/usr/bin/env bash
#
# run.sh — run the Socrate k6 scenarios and print a comparable summary.
#
# A baseline is only meaningful if every run is produced the same way, so this
# wraps the scenarios rather than leaving the invocation to memory.
#
# Usage:
#   ./run.sh                       # every scenario at its default rate
#   ./run.sh token_refresh         # one scenario
#   RATE=100 DURATION=60s ./run.sh # override the load shape
#
# Environment (see lib/config.js for the full list):
#   BASE_URL       default http://localhost:8080
#   CLIENT_ID      confidential client (default perf-client)
#   PUBLIC_CLIENT  public client for the refresh scenario (default perf-public)
#   RATE           requests/second
#   DURATION       e.g. 30s
#   VUS            pre-allocated virtual users
#   OUT            directory for the JSON summaries (default ./results)

set -euo pipefail

cd "$(dirname "$0")"

BASE_URL="${BASE_URL:-http://localhost:8080}"
PUBLIC_CLIENT="${PUBLIC_CLIENT:-perf-public}"
OUT="${OUT:-./results}"
mkdir -p "$OUT"

if ! command -v k6 >/dev/null 2>&1; then
  echo "k6 is not installed. Get it from https://k6.io/docs/get-started/installation/" >&2
  echo "or: go install go.k6.io/k6@latest" >&2
  exit 1
fi

if ! curl -fsS -o /dev/null "$BASE_URL/health"; then
  echo "No server answering at $BASE_URL/health — start Socrate and seed a client first." >&2
  echo "See docs/PERFORMANCE-BASELINE.md for the seeding step." >&2
  exit 1
fi

# Per-scenario defaults. The rates differ on purpose: the confidential-client
# scenarios are bcrypt-bound and collapse well below the rate the public paths
# sustain, so driving them all at one rate would measure a queue rather than a
# server. See docs/PERFORMANCE-BASELINE.md.
declare -A SCENARIO_RATE=(
  [discovery]=200
  [token_refresh]=100
  [login]=10
  [client_credentials]=10
  [introspect]=10
)
# Budgets are regression tripwires, not the measured numbers. They sit well
# above the baseline in docs/PERFORMANCE-BASELINE.md because the load generator
# shares CPU with the server: measured p95 for token_refresh is ~22 ms, but a
# co-located run shows a tail into the 80s. A gate that flaps teaches people to
# ignore it, so these catch a 5-10x regression rather than a 2x wobble.
declare -A SCENARIO_P95=(
  [discovery]=50
  [token_refresh]=150
  [login]=250
  [client_credentials]=450
  [introspect]=450
)

scenarios=("$@")
if [ ${#scenarios[@]} -eq 0 ]; then
  scenarios=(discovery token_refresh login client_credentials introspect)
fi

failed=0
for s in "${scenarios[@]}"; do
  if [ ! -f "$s.js" ]; then
    echo "unknown scenario: $s" >&2
    exit 1
  fi

  rate="${RATE:-${SCENARIO_RATE[$s]:-50}}"
  p95="${P95_MS:-${SCENARIO_P95[$s]:-100}}"
  duration="${DURATION:-30s}"
  vus="${VUS:-$rate}"

  # token_refresh runs against the public client: a confidential client would
  # make it a bcrypt benchmark instead of a refresh benchmark.
  client="${CLIENT_ID:-perf-client}"
  if [ "$s" = "token_refresh" ]; then
    client="$PUBLIC_CLIENT"
  fi

  echo
  echo "=== $s — ${rate} rps for ${duration}, p95 budget ${p95}ms ==="
  if BASE_URL="$BASE_URL" CLIENT_ID="$client" RATE="$rate" DURATION="$duration" \
     VUS="$vus" P95_MS="$p95" \
     k6 run --no-color --quiet --summary-export "$OUT/$s.json" "$s.js"; then
    echo "--- $s: PASS"
  else
    echo "--- $s: FAIL (threshold breached)" >&2
    failed=1
  fi
done

echo
echo "Summaries written to $OUT/"
exit $failed
