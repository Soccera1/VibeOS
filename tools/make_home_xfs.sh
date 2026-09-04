#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <output.xfs>" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
mkdir -m 0755 "$WORKDIR/root"
python3 "$SCRIPT_DIR/make_xfs_image.py" --writable "$WORKDIR/root" "$1"
