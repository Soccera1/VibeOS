#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <output-less> <less-src-dir> <ncurses-build-dir>" >&2
  exit 1
fi

OUT_BIN="$1"
SRC_DIR="$2"
NCURSES_BUILD="$3"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/strip_helpers.sh"

if [[ ! -d "$SRC_DIR" ]]; then
  echo "less source directory not found: $SRC_DIR" >&2
  exit 1
fi

if [[ -f "$NCURSES_BUILD/bin/ncursesw6-config" ]]; then
  NCURSES_CONFIG="$(cd "$NCURSES_BUILD" && pwd)/bin/ncursesw6-config"
else
  echo "ncursesw config script missing: $NCURSES_BUILD/bin/ncursesw6-config" >&2
  exit 1
fi

ABS_SRC_DIR="$(cd "$SRC_DIR" && pwd)"
BUILD_DIR="$ABS_SRC_DIR/build-musl"
BUILD_BIN="$BUILD_DIR/less"
CC_WRAPPER="$BUILD_DIR/zigcc-wrapper.sh"

mkdir -p "$(dirname "$OUT_BIN")"

prepare_zig_wrapper() {
  mkdir -p "$BUILD_DIR"
  cat > "$CC_WRAPPER" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

filtered=()
for arg in "$@"; do
  case "$arg" in
    -fuse-ld=*|--verbose|-static-libgcc|-fPIE|-fpie|-pie)
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
        -Map=*|-pie|--warn-common|--sort-common|--warn-execstack|--warn-rwx-segments|--verbose)
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

configure_less() {
  rm -rf "$BUILD_DIR"
  mkdir -p "$BUILD_DIR"
  prepare_zig_wrapper

  export ZIG_GLOBAL_CACHE_DIR="$REPO_ROOT/build/zig-global-cache"
  export ZIG_LOCAL_CACHE_DIR="$REPO_ROOT/build/zig-local-cache"
  mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"

  local ncurses_cflags
  local ncurses_libs
  ncurses_cflags="$("$NCURSES_CONFIG" --cflags)"
  ncurses_libs="$("$NCURSES_CONFIG" --libs)"

  pushd "$BUILD_DIR" >/dev/null
  "$ABS_SRC_DIR/configure" \
    --prefix=/usr \
    --host=x86_64-linux-musl \
    --with-regex=posix \
    CC="$CC_WRAPPER" \
    HOSTCC="${HOSTCC:-cc}" \
    AR="zig ar" \
    RANLIB="zig ranlib" \
    CPPFLAGS="$ncurses_cflags" \
    CFLAGS="-Os -fno-stack-protector -fomit-frame-pointer -fno-pie" \
    LDFLAGS="-static -no-pie $ncurses_libs" \
    LIBS="$ncurses_libs" \
    2>&1 | tee configure.log || {
      echo "Configure failed. Check $BUILD_DIR/configure.log" >&2
      exit 1
    }
  popd >/dev/null
}

build_less() {
  local ncurses_libs
  ncurses_libs="$("$NCURSES_CONFIG" --libs)"

  pushd "$BUILD_DIR" >/dev/null
  make -j1 less \
    CC="$CC_WRAPPER" \
    AR="zig ar" \
    RANLIB="zig ranlib" \
    CFLAGS="-Os -fno-stack-protector -fomit-frame-pointer -fno-pie" \
    LDFLAGS="-static -no-pie" \
    LIBS="$ncurses_libs" \
    2>&1 | tee build.log || {
      echo "Build failed. Check $BUILD_DIR/build.log" >&2
      exit 1
    }
  popd >/dev/null
}

validate_binary() {
  local bin="$1"
  if [[ ! -x "$bin" ]]; then
    echo "less binary is not executable: $bin" >&2
    return 1
  fi

  if ! readelf -h "$bin" | grep -q "Machine:[[:space:]]*Advanced Micro Devices X86-64"; then
    echo "less is not amd64: $bin" >&2
    return 1
  fi

  if ! readelf -h "$bin" | grep -q "Type:[[:space:]]*EXEC"; then
    echo "less must be non-PIE ET_EXEC for current loader: $bin" >&2
    return 1
  fi

  if readelf -l "$bin" | grep -q "Requesting program interpreter"; then
    echo "less must be static (no PT_INTERP): $bin" >&2
    return 1
  fi
}

configure_less
build_less
validate_binary "$BUILD_BIN"

cp "$BUILD_BIN" "$OUT_BIN"
chmod +x "$OUT_BIN"
maybe_strip_binary "$OUT_BIN"

echo "Built less: $OUT_BIN"
