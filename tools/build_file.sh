#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <output-file> <output-magic> <file-src-dir>" >&2
  exit 1
fi

OUT_BIN="$1"
OUT_MAGIC="$2"
SRC_DIR="$3"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ ! -d "$SRC_DIR" ]]; then
  echo "file source directory not found: $SRC_DIR" >&2
  exit 1
fi

ABS_SRC_DIR="$(cd "$SRC_DIR" && pwd)"

mkdir -p "$(dirname "$OUT_BIN")" "$(dirname "$OUT_MAGIC")"

BUILD_DIR="$ABS_SRC_DIR/build-musl"
BUILD_BIN="$BUILD_DIR/src/.libs/file"
BUILD_BIN_FALLBACK="$BUILD_DIR/src/file"
BUILD_MAGIC="$BUILD_DIR/magic/magic.mgc"
CC_WRAPPER="$BUILD_DIR/zigcc-wrapper.sh"

prepare_zig_wrapper() {
  mkdir -p "$BUILD_DIR"
  cat > "$CC_WRAPPER" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

filtered=()
for arg in "$@"; do
  case "$arg" in
    -fuse-ld=*|--verbose|-static-libgcc)
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

configure_file() {
  rm -rf "$BUILD_DIR"
  mkdir -p "$BUILD_DIR"
  prepare_zig_wrapper

  export ZIG_GLOBAL_CACHE_DIR="$REPO_ROOT/build/zig-global-cache"
  export ZIG_LOCAL_CACHE_DIR="$REPO_ROOT/build/zig-local-cache"
  mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"

  pushd "$BUILD_DIR" >/dev/null
  "$ABS_SRC_DIR/configure" \
    --prefix=/usr \
    --datadir=/usr/share \
    --disable-shared \
    --enable-static \
    --disable-zlib \
    --disable-bzlib \
    --disable-xzlib \
    --disable-zstdlib \
    --disable-lzlib \
    --disable-lrziplib \
    --disable-libseccomp \
    CC="$CC_WRAPPER" \
    HOSTCC="${HOSTCC:-cc}" \
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

build_file() {
  pushd "$BUILD_DIR" >/dev/null
  make -j1 -C src all \
    CC="$CC_WRAPPER" \
    AR="zig ar" \
    RANLIB="zig ranlib" \
    CFLAGS="-Os -fno-stack-protector -fomit-frame-pointer -fno-pie" \
    LDFLAGS="-static -no-pie" \
    2>&1 | tee build-src.log || {
      echo "Build failed. Check $BUILD_DIR/build-src.log" >&2
      exit 1
    }

  make -j1 -C magic magic.mgc \
    CC="$CC_WRAPPER" \
    AR="zig ar" \
    RANLIB="zig ranlib" \
    CFLAGS="-Os -fno-stack-protector -fomit-frame-pointer -fno-pie" \
    LDFLAGS="-static -no-pie" \
    2>&1 | tee build-magic.log || {
      echo "Build failed. Check $BUILD_DIR/build-magic.log" >&2
      exit 1
    }
  popd >/dev/null
}

validate_binary() {
  local bin="$1"
  if [[ ! -x "$bin" ]]; then
    echo "file binary is not executable: $bin" >&2
    return 1
  fi

  if ! readelf -h "$bin" | grep -q "Machine:[[:space:]]*Advanced Micro Devices X86-64"; then
    echo "file is not amd64: $bin" >&2
    return 1
  fi

  if ! readelf -h "$bin" | grep -q "Type:[[:space:]]*EXEC"; then
    echo "file must be non-PIE ET_EXEC for current loader: $bin" >&2
    return 1
  fi

  if readelf -l "$bin" | grep -q "Requesting program interpreter"; then
    echo "file must be static (no PT_INTERP): $bin" >&2
    return 1
  fi
}

configure_file
build_file

BIN_SOURCE="$BUILD_BIN"
if [[ ! -x "$BIN_SOURCE" ]]; then
  BIN_SOURCE="$BUILD_BIN_FALLBACK"
fi

if [[ ! -f "$BUILD_MAGIC" ]]; then
  echo "Compiled magic database missing: $BUILD_MAGIC" >&2
  exit 1
fi

validate_binary "$BIN_SOURCE"
cp "$BIN_SOURCE" "$OUT_BIN"
cp "$BUILD_MAGIC" "$OUT_MAGIC"
chmod +x "$OUT_BIN"

echo "Built file: $OUT_BIN"
echo "Built magic database: $OUT_MAGIC"
