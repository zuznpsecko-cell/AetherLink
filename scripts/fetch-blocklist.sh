#!/usr/bin/env bash
# Fetch the category-ads-all blocklist (flat suffix text) for the server.
# Same source as scripts/fetch-blocklist.ps1; the server reads it via
# `blocked_domains_file` (one suffix per line, `#` comments, leading dot
# means suffix). Re-run weekly/monthly to refresh.
#
# Usage: bash scripts/fetch-blocklist.sh [out-path]
# Default out: assets/blocklist-ads.txt (repo-relative when run from root).
set -euo pipefail

URL="${BLOCKLIST_URL:-https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/category-ads-all.txt}"
OUT="${1:-assets/blocklist-ads.txt}"

tmp="$(mktemp)"
trap 'rm -f "$tmp" "$tmp.clean"' EXIT
echo "Fetching $URL ..." >&2
curl -fsSL --max-time 120 "$URL" -o "$tmp"
mkdir -p "$(dirname "$OUT")"
# Normalize: lowercase, drop comments/blanks, strip clash prefixes, dedupe.
awk '
  { gsub(/\r/, ""); gsub(/^[ \t]+|[ \t]+$/, "") }
  /^$/ || /^#/ || /^!/ { next }
  { print tolower($0) }
' "$tmp" |
  sed -e 's/^domain-suffix,//; s/,.*$//' -e 's/^domain,//; s/,.*$//' |
  grep -v '^$' |
  sort -u >"$tmp.clean"
mv "$tmp.clean" "$OUT"
trap - EXIT
echo "Wrote $(wc -l <"$OUT") suffixes to $OUT"
echo "Point the server at it: blocked_domains_file: \"$OUT\""
