#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <output-tree> <groff-src-dir>" >&2
  exit 1
fi

OUT_DIR="$1"
SRC_DIR="$2"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/musl_toolchain.sh"
musl_init
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/strip_helpers.sh"

if [[ ! -d "$SRC_DIR" ]]; then
  echo "groff source directory not found: $SRC_DIR" >&2
  exit 1
fi

ABS_SRC_DIR="$(cd "$SRC_DIR" && pwd)"
mkdir -p "$(dirname "$OUT_DIR")"
OUT_DIR="$(cd "$(dirname "$OUT_DIR")" && pwd)/$(basename "$OUT_DIR")"

BUILD_DIR="$ABS_SRC_DIR/build-musl"
STAGE_DIR="$BUILD_DIR/stage"
CC_WRAPPER="$BUILD_DIR/muslcc-wrapper.sh"
CXX_WRAPPER="$BUILD_DIR/muslcxx-wrapper.sh"

prepare_musl_wrappers() {
  mkdir -p "$BUILD_DIR"
  musl_write_wrapper "$CC_WRAPPER" cc standard
  chmod +x "$CC_WRAPPER"

  musl_write_wrapper "$CXX_WRAPPER" c++ standard
  chmod +x "$CXX_WRAPPER"
}

configure_groff() {
  rm -rf "$BUILD_DIR"
  mkdir -p "$BUILD_DIR"
  prepare_musl_wrappers

  export ZIG_GLOBAL_CACHE_DIR="$REPO_ROOT/build/zig-global-cache"
  export ZIG_LOCAL_CACHE_DIR="$REPO_ROOT/build/zig-local-cache"
  mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"

  pushd "$BUILD_DIR" >/dev/null
  "$ABS_SRC_DIR/configure" \
    --prefix=/usr \
    --without-x \
    --with-uchardet=no \
    CC="$CC_WRAPPER" \
    CXX="$CXX_WRAPPER" \
    CPP="$CC_WRAPPER -E" \
    CXXCPP="$CXX_WRAPPER -E" \
    AR="$MUSL_AR" \
    RANLIB="$MUSL_RANLIB" \
    CFLAGS="-Os -fno-stack-protector -fomit-frame-pointer -fno-pie" \
    CXXFLAGS="-Os -fno-stack-protector -fomit-frame-pointer -fno-pie" \
    LDFLAGS="-static -no-pie" \
    2>&1 | tee configure.log || {
      echo "Configure failed. Check $BUILD_DIR/configure.log" >&2
      exit 1
    }
  popd >/dev/null
}

build_groff() {
  pushd "$BUILD_DIR" >/dev/null
  make -j1 2>&1 | tee build.log || {
    echo "Build failed. Check $BUILD_DIR/build.log" >&2
    exit 1
  }
  popd >/dev/null
}

stage_groff() {
  rm -rf "$STAGE_DIR" "$OUT_DIR"
  mkdir -p "$STAGE_DIR"

  pushd "$BUILD_DIR" >/dev/null
  make -j1 install DESTDIR="$STAGE_DIR" 2>&1 | tee install.log || {
    echo "Install failed. Check $BUILD_DIR/install.log" >&2
    exit 1
  }
  popd >/dev/null

  if [[ ! -x "$STAGE_DIR/usr/bin/groff" || ! -x "$STAGE_DIR/usr/bin/nroff" ]]; then
    echo "Expected groff/nroff binaries missing after install" >&2
    exit 1
  fi

  mkdir -p "$OUT_DIR"
  cp -a "$STAGE_DIR/usr/." "$OUT_DIR"/
  maybe_strip_tree_binaries "$OUT_DIR"
}

configure_groff
build_groff
stage_groff

echo "Built groff tree: $OUT_DIR"
