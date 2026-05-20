#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <name> <path>" >&2
  exit 1
fi

NAME="$1"
PATH_TO_CHECK="$2"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SUMS_FILE="$SCRIPT_DIR/distfile-sha256sums.txt"

if [[ ! -f "$PATH_TO_CHECK" ]]; then
  echo "distfile not found: $PATH_TO_CHECK" >&2
  exit 1
fi

EXPECTED="$(awk -v name="$NAME" '$2 == name { print $1 }' "$SUMS_FILE")"
if [[ -z "$EXPECTED" ]]; then
  echo "no pinned SHA-256 for distfile: $NAME" >&2
  exit 1
fi

ACTUAL="$(sha256sum "$PATH_TO_CHECK" | awk '{ print $1 }')"
if [[ "$ACTUAL" != "$EXPECTED" ]]; then
  echo "SHA-256 mismatch for $NAME" >&2
  echo "expected: $EXPECTED" >&2
  echo "actual:   $ACTUAL" >&2
  exit 1
fi
