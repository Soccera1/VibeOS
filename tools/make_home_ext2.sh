#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <output.ext3>" >&2
  exit 1
fi

OUT_IMG="$1"

mkdir -p "$(dirname "$OUT_IMG")"
truncate -s 64M "$OUT_IMG"
mkfs.ext3 -q -F -O ^dir_index -L VIBEOS_HOME "$OUT_IMG"
