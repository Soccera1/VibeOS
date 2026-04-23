#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <output.ext2>" >&2
  exit 1
fi

OUT_IMG="$1"

mkdir -p "$(dirname "$OUT_IMG")"
truncate -s 64M "$OUT_IMG"
mkfs.ext2 -q -F -L VIBEOS_HOME "$OUT_IMG"
