#!/usr/bin/env bash

set -euo pipefail

FILE="cp0.json"

# Ensure jq is available
if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: 'jq' is not installed or not in PATH." >&2
  exit 1
fi

# Ensure file exists
if [[ ! -f "$FILE" ]]; then
  echo "ERROR: $FILE not found in the current directory." >&2
  exit 1
fi

# 1) Validate JSON syntax
if ! jq -e . "$FILE" >/dev/null 2>&1; then
  echo "ERROR: Invalid JSON syntax in $FILE." >&2
  exit 1
fi

# 2) Check canonical formatting with sorted keys and 2-space indent
tmpfile="$(mktemp)"
cleanup() { rm -f "$tmpfile"; }
trap cleanup EXIT

# Produce canonical form
if ! jq -S --indent 2 . "$FILE" > "$tmpfile"; then
  echo "ERROR: Failed to reformat $FILE with jq." >&2
  exit 1
fi

# Byte-for-byte comparison
if ! cmp -s "$tmpfile" "$FILE"; then
  echo "ERROR: $FILE is not in canonical format (sorted keys, 2-space indent)." >&2
  echo "FIX:   jq -S --indent 2 . $FILE > ${FILE}.tmp && mv ${FILE}.tmp $FILE" >&2
  exit 1
fi

echo "OK: $FILE is valid and canonically formatted."
