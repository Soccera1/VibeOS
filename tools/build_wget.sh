#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 5 || $# -gt 6 ]]; then
  echo "usage: $0 <output-tree> <wget-src-dir> <gnutls-sysroot> <nettle-sysroot> <gmp-sysroot> [ca-bundle]" >&2
  exit 1
fi

OUT_DIR="$1"
SRC_DIR="$2"
GNUTLS_SYSROOT="$3"
NETTLE_SYSROOT="$4"
GMP_SYSROOT="$5"
CA_BUNDLE="${6:-}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/musl_toolchain.sh"
musl_init
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/strip_helpers.sh"

if [[ ! -d "$SRC_DIR" ]]; then
  echo "wget source directory not found: $SRC_DIR" >&2
  exit 1
fi

if [[ ! -f "$GNUTLS_SYSROOT/usr/include/gnutls/gnutls.h" || ! -f "$GNUTLS_SYSROOT/usr/lib/libgnutls.a" ]]; then
  echo "GnuTLS sysroot missing headers or static library: $GNUTLS_SYSROOT" >&2
  exit 1
fi

if [[ ! -f "$NETTLE_SYSROOT/usr/include/nettle/nettle-types.h" || ! -f "$NETTLE_SYSROOT/usr/lib/libnettle.a" || ! -f "$NETTLE_SYSROOT/usr/lib/libhogweed.a" ]]; then
  echo "Nettle sysroot missing headers or static libraries: $NETTLE_SYSROOT" >&2
  exit 1
fi

if [[ ! -f "$GMP_SYSROOT/usr/include/gmp.h" || ! -f "$GMP_SYSROOT/usr/lib/libgmp.a" ]]; then
  echo "GMP sysroot missing headers or static library: $GMP_SYSROOT" >&2
  exit 1
fi

ABS_SRC_DIR="$(cd "$SRC_DIR" && pwd)"
ABS_GNUTLS_SYSROOT="$(cd "$GNUTLS_SYSROOT" && pwd)"
ABS_NETTLE_SYSROOT="$(cd "$NETTLE_SYSROOT" && pwd)"
ABS_GMP_SYSROOT="$(cd "$GMP_SYSROOT" && pwd)"
mkdir -p "$(dirname "$OUT_DIR")"
OUT_DIR="$(cd "$(dirname "$OUT_DIR")" && pwd)/$(basename "$OUT_DIR")"

BUILD_DIR="$ABS_SRC_DIR/build-musl"
STAGE_DIR="$BUILD_DIR/stage"
BUILD_BIN="$BUILD_DIR/src/wget"
CC_WRAPPER="$BUILD_DIR/muslcc-wrapper.sh"
CA_CERT_PATH="/usr/etc/ssl/certs/ca-certificates.crt"

prepare_musl_wrapper() {
  mkdir -p "$BUILD_DIR"
  musl_write_wrapper "$CC_WRAPPER" cc standard
  chmod +x "$CC_WRAPPER"
}

configure_wget() {
  rm -rf "$BUILD_DIR"
  mkdir -p "$BUILD_DIR"
  prepare_musl_wrapper

  export ZIG_GLOBAL_CACHE_DIR="$REPO_ROOT/build/zig-global-cache"
  export ZIG_LOCAL_CACHE_DIR="$REPO_ROOT/build/zig-local-cache"
  mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"

  pushd "$BUILD_DIR" >/dev/null
  PKG_CONFIG=false \
  ac_cv_func_rawmemchr=no \
  "$ABS_SRC_DIR/configure" \
    --host=x86_64-linux-musl \
    --prefix=/usr \
    --sysconfdir=/usr/etc \
    --disable-nls \
    --disable-iri \
    --disable-pcre2 \
    --disable-pcre \
    --without-libpsl \
    --without-zlib \
    --without-libuuid \
    --with-ssl=gnutls \
    --with-libgnutls-prefix="$ABS_GNUTLS_SYSROOT/usr" \
    CC="$CC_WRAPPER" \
    HOSTCC="${HOSTCC:-cc}" \
    AR="$MUSL_AR" \
    RANLIB="$MUSL_RANLIB" \
    CFLAGS="-Os -fno-stack-protector -fomit-frame-pointer -fno-pie -I$ABS_GNUTLS_SYSROOT/usr/include -I$ABS_NETTLE_SYSROOT/usr/include -I$ABS_GMP_SYSROOT/usr/include" \
    LDFLAGS="-static -no-pie -L$ABS_GNUTLS_SYSROOT/usr/lib -L$ABS_NETTLE_SYSROOT/usr/lib -L$ABS_GMP_SYSROOT/usr/lib" \
    LIBS="-Wl,--start-group $ABS_GNUTLS_SYSROOT/usr/lib/libgnutls.a $ABS_NETTLE_SYSROOT/usr/lib/libhogweed.a $ABS_NETTLE_SYSROOT/usr/lib/libnettle.a $ABS_GMP_SYSROOT/usr/lib/libgmp.a -Wl,--end-group" \
    2>&1 | tee configure.log || {
      echo "Configure failed. Check $BUILD_DIR/configure.log" >&2
      exit 1
    }
  popd >/dev/null
}

build_wget() {
  pushd "$BUILD_DIR" >/dev/null
  make -j1 2>&1 | tee build.log || {
    echo "Build failed. Check $BUILD_DIR/build.log" >&2
    exit 1
  }
  popd >/dev/null
}

validate_binary() {
  local bin="$1"
  if [[ ! -x "$bin" ]]; then
    echo "wget binary is not executable: $bin" >&2
    return 1
  fi

  if ! readelf -h "$bin" | grep -q "Machine:[[:space:]]*Advanced Micro Devices X86-64"; then
    echo "wget is not amd64: $bin" >&2
    return 1
  fi

  if ! readelf -h "$bin" | grep -q "Type:[[:space:]]*EXEC"; then
    echo "wget must be non-PIE ET_EXEC for current loader: $bin" >&2
    return 1
  fi

  if readelf -l "$bin" | grep -q "Requesting program interpreter"; then
    echo "wget must be static (no PT_INTERP): $bin" >&2
    return 1
  fi

  if ! "$bin" --version | grep -q "+https"; then
    echo "wget was not built with HTTPS support" >&2
    return 1
  fi

  if ! "$bin" --version | grep -q "+ssl/gnutls"; then
    echo "wget was not built with HTTPS/GnuTLS support" >&2
    return 1
  fi
}

stage_wget() {
  rm -rf "$STAGE_DIR" "$OUT_DIR"
  mkdir -p "$STAGE_DIR/usr/bin" "$STAGE_DIR/usr/etc"

  validate_binary "$BUILD_BIN"
  cp "$BUILD_BIN" "$STAGE_DIR/usr/bin/wget"
  chmod +x "$STAGE_DIR/usr/bin/wget"
  maybe_strip_binary "$STAGE_DIR/usr/bin/wget"

  cat > "$STAGE_DIR/usr/etc/wgetrc" <<EOF
ca_certificate = $CA_CERT_PATH
EOF

  if [[ -n "$CA_BUNDLE" ]]; then
    if [[ ! -f "$CA_BUNDLE" ]]; then
      echo "CA bundle not found: $CA_BUNDLE" >&2
      exit 1
    fi
    mkdir -p "$STAGE_DIR/usr/etc/ssl/certs"
    cp "$CA_BUNDLE" "$STAGE_DIR/usr/etc/ssl/certs/ca-certificates.crt"
  fi

  mv "$STAGE_DIR/usr" "$OUT_DIR"
}

configure_wget
build_wget
stage_wget

echo "Built wget tree: $OUT_DIR"
