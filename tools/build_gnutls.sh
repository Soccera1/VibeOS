#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 <output-sysroot> <gnutls-src-dir> <nettle-sysroot> <gmp-sysroot>" >&2
  exit 1
fi

OUT_DIR="$1"
SRC_DIR="$2"
NETTLE_SYSROOT="$3"
GMP_SYSROOT="$4"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ ! -d "$SRC_DIR" ]]; then
  echo "GnuTLS source directory not found: $SRC_DIR" >&2
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
ABS_NETTLE_SYSROOT="$(cd "$NETTLE_SYSROOT" && pwd)"
ABS_GMP_SYSROOT="$(cd "$GMP_SYSROOT" && pwd)"
mkdir -p "$(dirname "$OUT_DIR")"
OUT_DIR="$(cd "$(dirname "$OUT_DIR")" && pwd)/$(basename "$OUT_DIR")"

BUILD_DIR="$ABS_SRC_DIR/build-musl"
STAGE_DIR="$BUILD_DIR/stage"
CC_WRAPPER="$BUILD_DIR/zigcc-wrapper.sh"

prepare_zig_wrapper() {
  mkdir -p "$BUILD_DIR"
  cat > "$CC_WRAPPER" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

filtered=()
for arg in "$@"; do
  case "$arg" in
    -fuse-ld=*|--verbose|-static-libgcc|-static-pie)
      continue
      ;;
  esac

  if [[ "$arg" == -Wl,* ]]; then
    payload="${arg#-Wl,}"
    IFS=',' read -r -a parts <<< "$payload"
    kept=()
    drop_next=0
    for part in "${parts[@]}"; do
      if (( drop_next )); then
        drop_next=0
        continue
      fi
      case "$part" in
        -Map)
          drop_next=1
          continue
          ;;
        -Map=*|--warn-common|--sort-common|--warn-execstack|--warn-rwx-segments|--verbose)
          continue
          ;;
      esac
      kept+=("$part")
    done
    if (( ${#kept[@]} > 0 )); then
      (IFS=','; filtered+=("-Wl,${kept[*]}"))
    fi
    continue
  fi

  filtered+=("$arg")
done

exec zig cc -target x86_64-linux-musl "${filtered[@]}"
EOF
  chmod +x "$CC_WRAPPER"
}

configure_gnutls() {
  rm -rf "$BUILD_DIR"
  mkdir -p "$BUILD_DIR"
  prepare_zig_wrapper

  export ZIG_GLOBAL_CACHE_DIR="$REPO_ROOT/build/zig-global-cache"
  export ZIG_LOCAL_CACHE_DIR="$REPO_ROOT/build/zig-local-cache"
  mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"

  pushd "$BUILD_DIR" >/dev/null
  PKG_CONFIG="${PKG_CONFIG:-pkg-config}" \
  PKG_CONFIG_LIBDIR=/nonexistent \
  NETTLE_CFLAGS="-I$ABS_NETTLE_SYSROOT/usr/include -I$ABS_GMP_SYSROOT/usr/include" \
  NETTLE_LIBS="$ABS_NETTLE_SYSROOT/usr/lib/libnettle.a $ABS_GMP_SYSROOT/usr/lib/libgmp.a" \
  HOGWEED_CFLAGS="-I$ABS_NETTLE_SYSROOT/usr/include -I$ABS_GMP_SYSROOT/usr/include" \
  HOGWEED_LIBS="$ABS_NETTLE_SYSROOT/usr/lib/libhogweed.a $ABS_NETTLE_SYSROOT/usr/lib/libnettle.a $ABS_GMP_SYSROOT/usr/lib/libgmp.a" \
  GMP_CFLAGS="-I$ABS_GMP_SYSROOT/usr/include" \
  GMP_LIBS="$ABS_GMP_SYSROOT/usr/lib/libgmp.a" \
  "$ABS_SRC_DIR/configure" \
    --host=x86_64-linux-musl \
    --prefix=/usr \
    --disable-shared \
    --enable-static \
    --disable-doc \
    --disable-tools \
    --disable-tests \
    --disable-cxx \
    --disable-nls \
    --disable-libdane \
    --disable-hardware-acceleration \
    --disable-padlock \
    --disable-ocsp \
    --disable-non-suiteb-curves \
    --disable-gost \
    --without-p11-kit \
    --without-idn \
    --without-zlib \
    --without-brotli \
    --without-zstd \
    --without-tpm \
    --without-tpm2 \
    --with-included-libtasn1 \
    --with-included-unistring \
    --with-default-trust-store-file=/usr/etc/ssl/certs/ca-certificates.crt \
    CC="$CC_WRAPPER" \
    HOSTCC="${HOSTCC:-cc}" \
    AR="zig ar" \
    RANLIB="zig ranlib" \
    CFLAGS="-Os -fno-stack-protector -fomit-frame-pointer -fno-pie -I$ABS_NETTLE_SYSROOT/usr/include -I$ABS_GMP_SYSROOT/usr/include" \
    LDFLAGS="-static -no-pie -L$ABS_NETTLE_SYSROOT/usr/lib -L$ABS_GMP_SYSROOT/usr/lib" \
    2>&1 | tee configure.log || {
      echo "Configure failed. Check $BUILD_DIR/configure.log" >&2
      exit 1
    }
  popd >/dev/null
}

build_gnutls() {
  pushd "$BUILD_DIR" >/dev/null
  make -j1 2>&1 | tee build.log || {
    echo "Build failed. Check $BUILD_DIR/build.log" >&2
    exit 1
  }
  popd >/dev/null
}

stage_gnutls() {
  rm -rf "$STAGE_DIR" "$OUT_DIR"
  pushd "$BUILD_DIR" >/dev/null
  make DESTDIR="$STAGE_DIR" install 2>&1 | tee install.log || {
    echo "Install failed. Check $BUILD_DIR/install.log" >&2
    exit 1
  }
  popd >/dev/null

  find "$STAGE_DIR/usr" -type f -name '*.la' -delete
  find "$STAGE_DIR/usr" -type f -name '*.so*' -delete

  if [[ ! -f "$STAGE_DIR/usr/include/gnutls/gnutls.h" || ! -f "$STAGE_DIR/usr/lib/libgnutls.a" ]]; then
    echo "GnuTLS install missing headers or static library" >&2
    exit 1
  fi

  local archive="$STAGE_DIR/usr/lib/libgnutls.a"
  local member
  while IFS= read -r member; do
    case "$member" in
      *.a)
        # Libtool embeds absolute static dependencies as archive members.
        # They are not relocatable objects and make some linkers reject
        # libgnutls.a; consumers already link Nettle and GMP explicitly.
        zig ar d "$archive" "$member"
        ;;
    esac
  done < <(zig ar t "$archive")

  if zig ar t "$archive" | grep -q '\.a$'; then
    echo "GnuTLS static library still contains nested archives" >&2
    exit 1
  fi

  zig ranlib "$archive"
  mv "$STAGE_DIR" "$OUT_DIR"
}

configure_gnutls
build_gnutls
stage_gnutls

echo "Built GnuTLS sysroot: $OUT_DIR"
