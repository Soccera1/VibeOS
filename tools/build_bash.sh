#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <output-bash> <bash-src-dir>" >&2
  exit 1
fi

OUT_BIN="$1"
SRC_DIR="$2"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/strip_helpers.sh"

mkdir -p "$(dirname "$OUT_BIN")"

BASH_BUILD="$(cd "$SRC_DIR" && pwd)/build-musl"
BASH_BIN_SRC="$(cd "$SRC_DIR" && pwd)/bash"

prepare_zig_cache() {
  local abs_src
  abs_src="$(cd "$SRC_DIR" && pwd)"
  export ZIG_GLOBAL_CACHE_DIR="$abs_src/.zig-global-cache"
  export ZIG_LOCAL_CACHE_DIR="$abs_src/.zig-local-cache"
  mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"
}

prepare_zig_wrapper() {
  local abs_src
  abs_src="$(cd "$SRC_DIR" && pwd)"
  local wrapper="$abs_src/.zigcc-musl-wrapper.sh"
  cat > "$wrapper" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

filtered=()
for arg in "$@"; do
  case "$arg" in
    -march=x86-64|-fuse-ld=*|--verbose|-static-libgcc|-finline-limit=0|-falign-jumps=1|-falign-labels=1)
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
  chmod +x "$wrapper"
  echo "$wrapper"
}

build_bash() {
  mkdir -p "$BASH_BUILD"
  prepare_zig_cache
  local ncurses_lib="$REPO_ROOT/external/ncurses-src/build-musl/lib"
  local ncurses_inc="$REPO_ROOT/external/ncurses-src/build-musl/include"
  local ncurses_inc_w="$REPO_ROOT/external/ncurses-src/build-musl/include/ncursesw"

  if [[ ! -f "$SRC_DIR/Makefile" || ! -f "$SRC_DIR/config.h" ]] || grep -q '^#define USING_BASH_MALLOC 1' "$SRC_DIR/config.h"; then
    CC_WRAPPER="$BASH_BUILD/zigcc-wrapper.sh"
    cat > "$CC_WRAPPER" <<'WRAPPER_EOF'
#!/usr/bin/env bash
set -euo pipefail
filtered=()
for arg in "$@"; do
  case "$arg" in
    -Wl,-rpath*|-Wl,--rpath*|-Wl,-soname*|-Wl,--soname*|-Wl,--version-script*|-Wl,--gc-sections)
      continue
      ;;
    -Wl,*)
      payload="${arg#-Wl,}"
      IFS=',' read -r -a parts <<< "$payload"
      kept=()
      for part in "${parts[@]}"; do
        case "$part" in
          -rpath*|--rpath*|-soname*|--soname*|--version-script*|--gc-sections)
            continue
            ;;
        esac
        kept+=("$part")
      done
      if (( ${#kept[@]} > 0 )); then
        (IFS=','; filtered+=("-Wl,${kept[*]}"))
      fi
      continue
      ;;
  esac
  filtered+=("$arg")
done
exec zig cc -target x86_64-linux-musl "${filtered[@]}"
WRAPPER_EOF
    chmod +x "$CC_WRAPPER"

    local extra_cflags="-mno-avx -mno-avx2 -mno-avx512f -fno-tree-vectorize -I$ncurses_inc -I$ncurses_inc_w -UHAVE_TERMCAP_H -DHAVE_NCURSES_TERMCAP_H=1"

    pushd "$SRC_DIR" >/dev/null
    rm -rf Makefile config.h bash builtins/Makefile lib/readline/Makefile lib/glob/Makefile lib/intl/Makefile lib/malloc/Makefile lib/sh/Makefile lib/termcap/Makefile lib/tilde/Makefile
    ./configure \
      --prefix="$BASH_BUILD" \
      --enable-static-link \
      --without-bash-malloc \
      --with-curses \
      --host=x86_64-linux-musl \
      CC="$CC_WRAPPER" \
      HOSTCC="${HOSTCC:-cc}" \
      BUILD_CC="${BUILD_CC:-cc}" \
      AR="zig ar" \
      RANLIB="zig ranlib" \
      CFLAGS="-Os -fno-stack-protector -fomit-frame-pointer -fno-exceptions -fno-asynchronous-unwind-tables $extra_cflags" \
      LDFLAGS="-static" \
      bash_cv_termcap_lib=libncursesw \
      2>&1 | tee "$BASH_BUILD/configure.log" || {
        echo "Configure failed. Check $BASH_BUILD/configure.log" >&2
        exit 1
      }
    
    popd >/dev/null
  fi

  pushd "$SRC_DIR" >/dev/null
  sed -i 's|^READLINE_LIB = .*|READLINE_LIB = -lreadline|' Makefile
  sed -i 's|^HISTORY_LIB = .*|HISTORY_LIB = -lhistory|' Makefile
  sed -i 's|^BUILTINS_LIB = .*|BUILTINS_LIB = -lbuiltins|' Makefile
  sed -i "s|^TERMCAP_LIB = .*|TERMCAP_LIB = -L$ncurses_lib -lncursesw -L$ncurses_lib -ltinfow|" Makefile
  popd >/dev/null

  if [[ ! -f "$BASH_BIN_SRC" ]]; then
    local cc_cmd="$BASH_BUILD/zigcc-wrapper.sh"

    pushd "$SRC_DIR" >/dev/null
    make -j1 \
      CC="$cc_cmd" \
      AR="zig ar" \
      RANLIB="zig ranlib" \
      CFLAGS="-Os -mno-avx -mno-avx2 -mno-avx512f -fno-tree-vectorize -I$ncurses_inc -I$ncurses_inc_w -UHAVE_TERMCAP_H -DHAVE_NCURSES_TERMCAP_H=1" \
      LDFLAGS="-static" \
      2>&1 | tee "$BASH_BUILD/build.log" || {
        echo "Make failed. Check $BASH_BUILD/build.log" >&2
        exit 1
      }
    popd >/dev/null
  fi

  cp "$BASH_BIN_SRC" "$OUT_BIN"
  chmod +x "$OUT_BIN"
  maybe_strip_binary "$OUT_BIN"
  echo "Built bash: $OUT_BIN"
}

validate_bash_binary() {
  local bin="$1"
  if [[ ! -x "$bin" ]]; then
    echo "Bash binary is not executable: $bin" >&2
    return 1
  fi

  if ! readelf -h "$bin" | grep -q "Machine:[[:space:]]*Advanced Micro Devices X86-64"; then
    echo "Bash is not amd64: $bin" >&2
    return 1
  fi

  if ! readelf -h "$bin" | grep -q "Type:[[:space:]]*EXEC"; then
    echo "Bash must be non-PIE ET_EXEC for current loader: $bin" >&2
    return 1
  fi

  if readelf -l "$bin" | grep -q "Requesting program interpreter"; then
    echo "Bash must be static (no PT_INTERP): $bin" >&2
    return 1
  fi
}

if [[ ! -d "$SRC_DIR" ]]; then
  echo "Bash source directory not found: $SRC_DIR" >&2
  exit 1
fi

build_bash

if [[ -x "$OUT_BIN" ]]; then
  validate_bash_binary "$OUT_BIN"
fi
