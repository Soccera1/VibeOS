#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <output-nano> <nano-src-dir>" >&2
  exit 1
fi

OUT_BIN="$1"
SRC_DIR="$2"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/musl_toolchain.sh"
musl_init
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/strip_helpers.sh"

if [[ ! -d "$SRC_DIR" ]]; then
  echo "nano source directory not found: $SRC_DIR" >&2
  exit 1
fi

ABS_SRC_DIR="$(cd "$SRC_DIR" && pwd)"
BUILD_DIR="$ABS_SRC_DIR/build-musl"
BUILD_BIN="$BUILD_DIR/src/nano"
CC_WRAPPER="$BUILD_DIR/muslcc-wrapper.sh"
NCURSES_PREFIX="$REPO_ROOT/external/ncurses-src/build-musl"
NCURSES_CONFIG="$NCURSES_PREFIX/bin/ncursesw6-config"

mkdir -p "$(dirname "$OUT_BIN")"

prepare_musl_wrapper() {
  mkdir -p "$BUILD_DIR"
  musl_write_wrapper "$CC_WRAPPER" cc standard
  chmod +x "$CC_WRAPPER"
}

configure_nano() {
  if [[ ! -x "$NCURSES_CONFIG" ]]; then
    echo "ncursesw config script missing: $NCURSES_CONFIG" >&2
    exit 1
  fi

  rm -rf "$BUILD_DIR"
  mkdir -p "$BUILD_DIR"
  prepare_musl_wrapper

  export ZIG_GLOBAL_CACHE_DIR="$REPO_ROOT/build/zig-global-cache"
  export ZIG_LOCAL_CACHE_DIR="$REPO_ROOT/build/zig-local-cache"
  mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"

  local ncurses_cflags
  local ncurses_libs
  ncurses_cflags="$("$NCURSES_CONFIG" --cflags)"
  ncurses_libs="$("$NCURSES_CONFIG" --libs)"

  pushd "$BUILD_DIR" >/dev/null
  PKG_CONFIG=/bin/false \
  NCURSESW_CONFIG="$NCURSES_CONFIG" \
  "$ABS_SRC_DIR/configure" \
    --prefix=/usr \
    --disable-nls \
    --disable-libmagic \
    --host=x86_64-linux-musl \
    CC="$CC_WRAPPER" \
    HOSTCC="${HOSTCC:-cc}" \
    AR="$MUSL_AR" \
    RANLIB="$MUSL_RANLIB" \
    CPPFLAGS="$ncurses_cflags" \
    CFLAGS="-Os -fno-stack-protector -fomit-frame-pointer -fno-pie" \
    LDFLAGS="-static -no-pie $ncurses_libs" \
    2>&1 | tee configure.log || {
      echo "Configure failed. Check $BUILD_DIR/configure.log" >&2
      exit 1
    }
  popd >/dev/null
}

build_nano() {
  pushd "$BUILD_DIR" >/dev/null
  make -j1 -C lib all \
    CC="$CC_WRAPPER" \
    AR="$MUSL_AR" \
    RANLIB="$MUSL_RANLIB" \
    CFLAGS="-Os -fno-stack-protector -fomit-frame-pointer -fno-pie" \
    LDFLAGS="-static -no-pie" \
    2>&1 | tee build.log || {
      echo "Build failed. Check $BUILD_DIR/build.log" >&2
      exit 1
    }

  make -j1 -C src nano \
    CC="$CC_WRAPPER" \
    AR="$MUSL_AR" \
    RANLIB="$MUSL_RANLIB" \
    CFLAGS="-Os -fno-stack-protector -fomit-frame-pointer -fno-pie" \
    LDFLAGS="-static -no-pie" \
    2>&1 | tee build.log || {
      echo "Build failed. Check $BUILD_DIR/build.log" >&2
      exit 1
    }
  popd >/dev/null
}

validate_binary() {
  local bin="$1"
  if [[ ! -x "$bin" ]]; then
    echo "nano binary is not executable: $bin" >&2
    return 1
  fi

  if ! readelf -h "$bin" | grep -q "Machine:[[:space:]]*Advanced Micro Devices X86-64"; then
    echo "nano is not amd64: $bin" >&2
    return 1
  fi

  if ! readelf -h "$bin" | grep -q "Type:[[:space:]]*EXEC"; then
    echo "nano must be non-PIE ET_EXEC for current loader: $bin" >&2
    return 1
  fi

  if readelf -l "$bin" | grep -q "Requesting program interpreter"; then
    echo "nano must be static (no PT_INTERP): $bin" >&2
    return 1
  fi
}

configure_nano
build_nano
validate_binary "$BUILD_BIN"

cp "$BUILD_BIN" "$OUT_BIN"
chmod +x "$OUT_BIN"
maybe_strip_binary "$OUT_BIN"

echo "Built nano: $OUT_BIN"
