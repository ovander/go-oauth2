#!/usr/bin/env bash
# Tier A (security-critical) coverage ratchet — docs/program/TEST-STRATEGY.md.
#
# Fails if Tier A coverage drops below TIER_A_MIN. This is a ratchet: the floor
# starts at the current baseline and is raised toward the ≥90% target as the
# test suites grow, so coverage can only go up. Blocking in CI (Phase 8).
set -euo pipefail

FLOOR="${TIER_A_MIN:-55.0}"
# internal/policy (A4) is Tier A: it decides who may use the admin API.
TIER_A="./internal/service/...,./internal/shared/auth/...,./internal/middleware/...,./internal/policy/...,./config/..."

go test ./internal/service/... ./internal/shared/auth/... ./internal/middleware/... ./internal/policy/... ./config/... \
  -coverpkg="$TIER_A" -coverprofile=tierA.out >/dev/null

COV="$(go tool cover -func=tierA.out | tail -1 | awk '{print $3}' | tr -d '%')"
echo "Tier A coverage: ${COV}%  (floor: ${FLOOR}%)"

if awk -v c="$COV" -v f="$FLOOR" 'BEGIN { exit !(c+0 >= f+0) }'; then
  echo "✅ Tier A coverage gate passed."
else
  echo "❌ Tier A coverage ${COV}% is below the floor ${FLOOR}%."
  echo "   Add tests for the security-critical packages, or do not lower coverage."
  exit 1
fi
