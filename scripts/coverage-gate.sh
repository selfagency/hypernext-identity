#!/usr/bin/env bash
# Coverage gate: fail if total Go coverage drops below 80%.
# Runs a coverage-only pass (no -race, no MinIO) — fast enough for pre-commit.
set -euo pipefail

THRESHOLD="${COVERAGE_THRESHOLD:-80}"
COV_FILE="$(mktemp)"
trap 'rm -f "$COV_FILE"' EXIT

# Coverage-only run; suppress test output, keep the profile.
go test ./... -coverprofile="$COV_FILE" -covermode=atomic >/dev/null 2>&1

total="$(go tool cover -func="$COV_FILE" | tail -1 | awk '{print $NF}' | tr -d '%')"
echo "Coverage: ${total}%"

if (( $(echo "$total < $THRESHOLD" | bc -l) )); then
  echo "Coverage ${total}% is below the ${THRESHOLD}% threshold" >&2
  exit 1
fi
