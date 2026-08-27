#!/usr/bin/env bash
# docs-links.sh — check that relative Markdown links in docs/ and the root
# Markdown files resolve to files that exist.
#
# This is a fast, offline, GitHub-flavored link check: it validates that every
# relative link target (foo.md, ../bar.md, dir/, #anchors are skipped for
# target-existence) points at a real file on disk. External (http/https)
# links are NOT fetched here — that is left to a full link crawler in CI.
#
# Exit 0 = no broken relative links. Exit 1 = one or more broken links.

set -euo pipefail

cd "$(dirname "$0")/.."

fail=0
count=0

# Gather the Markdown files we own: docs/ + root *.md (README, CONTRIBUTING,
# SECURITY, CHANGELOG). Exclude the Hugo project (docs/site), build output,
# and _templates (authoring-only scaffolds with intentional placeholders).
mapfile -t files < <(find docs -name '*.md' -not -path 'docs/site/*' -not -path 'docs/public/*' -not -path 'docs/_templates/*'; \
                     ls ./*.md 2>/dev/null || true)

# Extract link targets from Markdown inline/reference links: ](target)
# We only check relative targets (not http(s)://, mailto:, or pure #anchors).
extract() {
  grep -oE '\]\(([^)]+)\)' "$1" \
    | sed -E 's/^\]\(//; s/\)$//' \
    | awk '{print $1}' \
    | sed -E 's/^<//; s/>$//' || true
}

for f in "${files[@]}"; do
  [[ -f "$f" ]] || continue
  dir=$(dirname "$f")
  while IFS= read -r target; do
    [[ -z "$target" ]] && continue
    case "$target" in
      http://*|https://*|mailto:*|\#*|/*) continue ;;  # skip external/anchor/absolute
    esac
    # Strip any #fragment from the target before resolving.
    path="${target%%#*}"
    [[ -z "$path" ]] && continue
    count=$((count + 1))
    # Resolve relative to the file's directory.
    if [[ -e "$dir/$path" ]]; then
      :
    else
      echo "  ✗ $f -> $target (resolved: $dir/$path)" >&2
      fail=1
    fi
  done < <(extract "$f")
done

echo
if [[ "$fail" -ne 0 ]]; then
  echo "docs-links: FAILED ($count relative links checked)" >&2
  exit 1
fi
echo "docs-links: OK ($count relative links resolve)"
