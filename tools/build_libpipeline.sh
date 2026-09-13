#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <output-sysroot> <libpipeline-src-dir>" >&2
  exit 1
fi

OUT_DIR="$1"
SRC_DIR="$2"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/musl_toolchain.sh"
musl_init
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ ! -d "$SRC_DIR" ]]; then
  echo "libpipeline source directory not found: $SRC_DIR" >&2
  exit 1
fi

ABS_SRC_DIR="$(cd "$SRC_DIR" && pwd)"
mkdir -p "$(dirname "$OUT_DIR")"
OUT_DIR="$(cd "$(dirname "$OUT_DIR")" && pwd)/$(basename "$OUT_DIR")"

BUILD_DIR="$ABS_SRC_DIR/build-musl"
STAGE_DIR="$BUILD_DIR/stage"
CC_WRAPPER="$BUILD_DIR/muslcc-wrapper.sh"

prepare_musl_wrapper() {
  mkdir -p "$BUILD_DIR"
  musl_write_wrapper "$CC_WRAPPER" cc standard
  chmod +x "$CC_WRAPPER"
}

configure_libpipeline() {
  rm -rf "$BUILD_DIR"
  mkdir -p "$BUILD_DIR"
  prepare_musl_wrapper

  export ZIG_GLOBAL_CACHE_DIR="$REPO_ROOT/build/zig-global-cache"
  export ZIG_LOCAL_CACHE_DIR="$REPO_ROOT/build/zig-local-cache"
  mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"

  pushd "$BUILD_DIR" >/dev/null
  "$ABS_SRC_DIR/configure" \
    --prefix=/usr \
    --libdir=/usr/lib64 \
    --disable-shared \
    --enable-static \
    --disable-dependency-tracking \
    --enable-gcc-warnings=no \
    CC="$CC_WRAPPER" \
    CPP="$CC_WRAPPER -E" \
    AR="$MUSL_AR" \
    RANLIB="$MUSL_RANLIB" \
    CFLAGS="-Os -fno-stack-protector -fomit-frame-pointer -fno-pie" \
    LDFLAGS="-static -no-pie" \
    2>&1 | tee configure.log || {
      echo "Configure failed. Check $BUILD_DIR/configure.log" >&2
      exit 1
    }
  popd >/dev/null
}

build_libpipeline() {
  pushd "$BUILD_DIR" >/dev/null
  make -j1 2>&1 | tee build.log || {
    echo "Build failed. Check $BUILD_DIR/build.log" >&2
    exit 1
  }
  popd >/dev/null
}

stage_libpipeline() {
  rm -rf "$STAGE_DIR" "$OUT_DIR"
  mkdir -p "$STAGE_DIR"

  pushd "$BUILD_DIR" >/dev/null
  make -j1 install DESTDIR="$STAGE_DIR" 2>&1 | tee install.log || {
    echo "Install failed. Check $BUILD_DIR/install.log" >&2
    exit 1
  }
  popd >/dev/null

  if [[ ! -f "$STAGE_DIR/usr/lib64/libpipeline.a" ]]; then
    echo "Static libpipeline archive missing after install" >&2
    exit 1
  fi

  cp -a "$STAGE_DIR/." "$OUT_DIR"
  mkdir -p "$OUT_DIR/usr/lib"
  rm -f "$OUT_DIR/usr/lib64/libpipeline.la"
}

configure_libpipeline
build_libpipeline
stage_libpipeline

echo "Built libpipeline sysroot: $OUT_DIR"
