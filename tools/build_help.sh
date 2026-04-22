#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <output-bin> <source-file>" >&2
  exit 1
fi

OUT_BIN="$1"
SRC_FILE="$2"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/strip_helpers.sh"

mkdir -p "$(dirname "$OUT_BIN")"

if [[ ! -f "$SRC_FILE" ]]; then
  echo "Help source not found: $SRC_FILE" >&2
  exit 1
fi

export ZIG_GLOBAL_CACHE_DIR="$REPO_ROOT/build/zig-global-cache"
export ZIG_LOCAL_CACHE_DIR="$REPO_ROOT/build/zig-local-cache"
mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"

zig cc -target x86_64-linux-musl \
  -Os \
  -static \
  -no-pie \
  -fno-stack-protector \
  -fomit-frame-pointer \
  -o "$OUT_BIN" \
  "$SRC_FILE"

chmod +x "$OUT_BIN"
maybe_strip_binary "$OUT_BIN"

if ! readelf -h "$OUT_BIN" | grep -q "Machine:[[:space:]]*Advanced Micro Devices X86-64"; then
  echo "Help binary is not amd64: $OUT_BIN" >&2
  exit 1
fi

if ! readelf -h "$OUT_BIN" | grep -q "Type:[[:space:]]*EXEC"; then
  echo "Help binary must be non-PIE ET_EXEC: $OUT_BIN" >&2
  exit 1
fi

if readelf -l "$OUT_BIN" | grep -q "Requesting program interpreter"; then
  echo "Help binary must be static (no PT_INTERP): $OUT_BIN" >&2
  exit 1
fi

echo "Built help: $OUT_BIN"
