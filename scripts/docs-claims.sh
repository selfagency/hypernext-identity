#!/usr/bin/env bash
# docs-claims.sh — verify that the README's advertised capabilities are real.
#
# The README contains a machine-readable claims block between
#   <!-- claims
#   ...pipe-separated rows:  slug | kind | value
#   claims -->
#
# kind=route  → the literal value (a route prefix) MUST appear as a
#               mux.Handle("...") argument in internal/server/server.go.
# kind=pkg    → the value (a package dir) MUST exist AND contain at least
#               one *_test.go file (the "backing test" requirement).
#
# This is the honesty gate: a capability may not be marketed as "Shipped"
# unless it is BOTH reachable (route) and tested (pkg). If you add a Shipped
# row to the README table, you must add a matching, passing claim here.
#
# Exit 0 = all claims verified. Exit 1 = one or more claims failed.

set -euo pipefail

cd "$(dirname "$0")/.."

README="README.md"
SERVER="internal/server/server.go"

if [[ ! -f "$README" ]]; then
  echo "docs-claims: $README not found" >&2
  exit 1
fi

# Extract lines between the claims markers, strip HTML-comment/leading space.
claims=$(awk '/<!-- claims/{f=1;next} /^claims -->/{f=0} f' "$README" | sed 's/[[:space:]]*$//' | grep -v '^[[:space:]]*$' || true)

if [[ -z "$claims" ]]; then
  echo "docs-claims: no claims block found in $README" >&2
  echo "  expected a block between '<!-- claims' and 'claims -->'" >&2
  exit 1
fi

fail=0
count=0

while IFS= read -r line; do
  # Split "slug | kind | value".
  slug=$(printf '%s' "$line"   | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/,"",$1); print $1}')
  kind=$(printf '%s' "$line"   | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2}')
  value=$(printf '%s' "$line"  | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/,"",$3); print $3}')

  if [[ -z "$slug" || -z "$kind" || -z "$value" ]]; then
    echo "  ✗ malformed claim line: $line" >&2
    fail=1
    continue
  fi
  count=$((count + 1))

  case "$kind" in
    route)
      # The literal route must be a mux.Handle argument in server.go.
      if grep -Fq "mux.Handle(\"$value\"" "$SERVER"; then
        echo "  ✓ route  $slug  ($value)"
      else
        echo "  ✗ route  $slug  — \"$value\" not mounted in $SERVER" >&2
        fail=1
      fi
      ;;
    pkg)
      if [[ ! -d "$value" ]]; then
        echo "  ✗ pkg    $slug  — directory $value does not exist" >&2
        fail=1
      elif ! find "$value" -name '*_test.go' -print -quit | grep -q .; then
        echo "  ✗ pkg    $slug  — no *_test.go under $value (no backing test)" >&2
        fail=1
      else
        echo "  ✓ pkg    $slug  ($value)"
      fi
      ;;
    *)
      echo "  ✗ unknown claim kind \"$kind\" for $slug (want route|pkg)" >&2
      fail=1
      ;;
  esac
done <<< "$claims"

echo
if [[ "$fail" -ne 0 ]]; then
  echo "docs-claims: FAILED ($count claims checked)" >&2
  exit 1
fi
echo "docs-claims: OK ($count claims verified)"
