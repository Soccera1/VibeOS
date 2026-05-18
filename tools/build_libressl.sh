#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <output-sysroot> <libressl-src-dir>" >&2
  exit 1
fi

OUT_DIR="$1"
SRC_DIR="$2"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ ! -d "$SRC_DIR" ]]; then
  echo "LibreSSL source directory not found: $SRC_DIR" >&2
  exit 1
fi

ABS_SRC_DIR="$(cd "$SRC_DIR" && pwd)"
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

configure_libressl() {
  rm -rf "$BUILD_DIR"
  mkdir -p "$BUILD_DIR"
  prepare_zig_wrapper

  export ZIG_GLOBAL_CACHE_DIR="$REPO_ROOT/build/zig-global-cache"
  export ZIG_LOCAL_CACHE_DIR="$REPO_ROOT/build/zig-local-cache"
  mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"

  pushd "$BUILD_DIR" >/dev/null
  "$ABS_SRC_DIR/configure" \
    --host=x86_64-linux-musl \
    --prefix=/usr \
    --disable-shared \
    --enable-static \
    CC="$CC_WRAPPER" \
    AR="zig ar" \
    RANLIB="zig ranlib" \
    CFLAGS="-Os -fno-stack-protector -fomit-frame-pointer -fno-pie" \
    LDFLAGS="-static -no-pie" \
    2>&1 | tee configure.log || {
      echo "Configure failed. Check $BUILD_DIR/configure.log" >&2
      exit 1
    }
  popd >/dev/null
}

build_libressl() {
  pushd "$BUILD_DIR" >/dev/null
  make -j1 2>&1 | tee build.log || {
    echo "Build failed. Check $BUILD_DIR/build.log" >&2
    exit 1
  }
  popd >/dev/null
}

stage_libressl() {
  rm -rf "$STAGE_DIR" "$OUT_DIR"
  mkdir -p "$STAGE_DIR/usr/include" "$STAGE_DIR/usr/lib"

  cp -a "$ABS_SRC_DIR/include/openssl" "$STAGE_DIR/usr/include/"
  cp -a "$BUILD_DIR/include/openssl/opensslconf.h" "$STAGE_DIR/usr/include/openssl/"
  cp -a "$ABS_SRC_DIR/include/tls.h" "$STAGE_DIR/usr/include/"
  cp -a "$BUILD_DIR/crypto/.libs/libcrypto.a" "$STAGE_DIR/usr/lib/"
  cp -a "$BUILD_DIR/ssl/.libs/libssl.a" "$STAGE_DIR/usr/lib/"
  cp -a "$BUILD_DIR/tls/.libs/libtls.a" "$STAGE_DIR/usr/lib/"

  zig ranlib "$STAGE_DIR/usr/lib/libcrypto.a"
  zig ranlib "$STAGE_DIR/usr/lib/libssl.a"
  zig ranlib "$STAGE_DIR/usr/lib/libtls.a"

  mv "$STAGE_DIR" "$OUT_DIR"
}

configure_libressl
build_libressl
stage_libressl

echo "Built LibreSSL sysroot: $OUT_DIR"
