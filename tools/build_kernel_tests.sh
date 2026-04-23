#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <output-root> <tests-dir>" >&2
  exit 1
fi

OUT_ROOT="$1"
TESTS_DIR="$2"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/strip_helpers.sh"

if [[ ! -d "$TESTS_DIR" ]]; then
  echo "tests directory not found: $TESTS_DIR" >&2
  exit 1
fi

validate_binary() {
  local bin="$1"

  if [[ ! -x "$bin" ]]; then
    echo "test binary is not executable: $bin" >&2
    return 1
  fi

  if ! readelf -h "$bin" | grep -q "Machine:[[:space:]]*Advanced Micro Devices X86-64"; then
    echo "test binary is not amd64: $bin" >&2
    return 1
  fi

  if ! readelf -h "$bin" | grep -q "Type:[[:space:]]*EXEC"; then
    echo "test binary must be non-PIE ET_EXEC: $bin" >&2
    return 1
  fi

  if readelf -l "$bin" | grep -q "Requesting program interpreter"; then
    echo "test binary must be static (no PT_INTERP): $bin" >&2
    return 1
  fi
}

rm -rf "$OUT_ROOT"
mkdir -p "$OUT_ROOT/bin" "$OUT_ROOT/libexec/kernel-tests" "$OUT_ROOT/share/kernel-tests"

export ZIG_GLOBAL_CACHE_DIR="$REPO_ROOT/build/zig-global-cache"
export ZIG_LOCAL_CACHE_DIR="$REPO_ROOT/build/zig-local-cache"
mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"

COMMON_FLAGS=(
  -target x86_64-linux-musl
  -Os
  -static
  -no-pie
  -fno-stack-protector
  -fomit-frame-pointer
  -Wall
  -Wextra
  -Werror
)

zig cc "${COMMON_FLAGS[@]}" \
  -o "$OUT_ROOT/bin/kernel-tests" \
  "$TESTS_DIR/kernel-tests.c"

zig cc "${COMMON_FLAGS[@]}" \
  -o "$OUT_ROOT/libexec/kernel-tests/kernel-test-helper" \
  "$TESTS_DIR/kernel-test-helper.c"

ln -sfn ../../libexec/kernel-tests/kernel-test-helper "$OUT_ROOT/share/kernel-tests/helper-link"

chmod +x "$OUT_ROOT/bin/kernel-tests" "$OUT_ROOT/libexec/kernel-tests/kernel-test-helper"
validate_binary "$OUT_ROOT/bin/kernel-tests"
validate_binary "$OUT_ROOT/libexec/kernel-tests/kernel-test-helper"
maybe_strip_tree_binaries "$OUT_ROOT"

echo "Built kernel tests under: $OUT_ROOT"
