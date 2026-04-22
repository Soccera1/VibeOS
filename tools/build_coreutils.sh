#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <output-coreutils-dir> <output-programs> <coreutils-src-dir>" >&2
  exit 1
fi

OUT_DIR="$1"
OUT_PROGS="$2"
SRC_DIR="$3"

if [[ ! -d "$SRC_DIR" ]]; then
  echo "coreutils source directory not found: $SRC_DIR" >&2
  exit 1
fi

ABS_SRC_DIR="$(cd "$SRC_DIR" && pwd)"

mkdir -p "$(dirname "$OUT_DIR")" "$(dirname "$OUT_PROGS")"

BUILD_DIR="$ABS_SRC_DIR/build-musl"
STAGE_DIR="$BUILD_DIR/package"
STAGE_BIN_DIR="$STAGE_DIR/usr/bin"
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

configure_coreutils() {
  rm -rf "$BUILD_DIR"
  mkdir -p "$BUILD_DIR"
  prepare_zig_wrapper

  export ZIG_GLOBAL_CACHE_DIR="$ABS_SRC_DIR/.zig-global-cache"
  export ZIG_LOCAL_CACHE_DIR="$ABS_SRC_DIR/.zig-local-cache"
  mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"

  pushd "$BUILD_DIR" >/dev/null
  "$ABS_SRC_DIR/configure" \
    --host=x86_64-linux-musl \
    --prefix=/usr \
    --disable-nls \
    CC="$CC_WRAPPER" \
    HOSTCC="${HOSTCC:-cc}" \
    BUILD_CC="${BUILD_CC:-cc}" \
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

build_coreutils() {
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
    echo "coreutils binary is not executable: $bin" >&2
    return 1
  fi

  if ! readelf -h "$bin" | grep -q "Machine:[[:space:]]*Advanced Micro Devices X86-64"; then
    echo "coreutils is not amd64: $bin" >&2
    return 1
  fi

  if ! readelf -h "$bin" | grep -q "Type:[[:space:]]*EXEC"; then
    echo "coreutils must be non-PIE ET_EXEC for current loader: $bin" >&2
    return 1
  fi

  if readelf -l "$bin" | grep -q "Requesting program interpreter"; then
    echo "coreutils must be static (no PT_INTERP): $bin" >&2
    return 1
  fi
}

stage_coreutils() {
  rm -rf "$STAGE_DIR"
  mkdir -p "$STAGE_DIR"

  pushd "$BUILD_DIR" >/dev/null
  make -j1 install-binPROGRAMS DESTDIR="$STAGE_DIR" 2>&1 | tee install.log || {
    echo "Install failed. Check $BUILD_DIR/install.log" >&2
    exit 1
  }
  popd >/dev/null

  if [[ ! -d "$STAGE_BIN_DIR" ]]; then
    echo "Expected installed coreutils directory missing: $STAGE_BIN_DIR" >&2
    exit 1
  fi
}

copy_programs() {
  rm -rf "$OUT_DIR"
  mkdir -p "$OUT_DIR"
  : > "$OUT_PROGS"

  local prog
  while IFS= read -r prog; do
    [[ -n "$prog" ]] || continue
    validate_binary "$STAGE_BIN_DIR/$prog"
    cp "$STAGE_BIN_DIR/$prog" "$OUT_DIR/$prog"
    chmod +x "$OUT_DIR/$prog"
    printf '%s\n' "$prog" >> "$OUT_PROGS"
  done < <(find "$STAGE_BIN_DIR" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort)
}

configure_coreutils
build_coreutils
stage_coreutils
copy_programs

echo "Built coreutils directory: $OUT_DIR"
echo "Wrote coreutils program list: $OUT_PROGS"
