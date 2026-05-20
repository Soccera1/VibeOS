#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <output-tree> <vim-src-dir> <ncurses-build-dir>" >&2
  exit 1
fi

OUT_TREE="$1"
SRC_DIR="$2"
NCURSES_BUILD="$3"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/strip_helpers.sh"

if [[ ! -d "$SRC_DIR" ]]; then
  echo "Vim source directory not found: $SRC_DIR" >&2
  exit 1
fi

if [[ -f "$NCURSES_BUILD/bin/ncursesw6-config" ]]; then
  ABS_NCURSES_BUILD="$(cd "$NCURSES_BUILD" && pwd)"
  NCURSES_CONFIG="$ABS_NCURSES_BUILD/bin/ncursesw6-config"
else
  echo "ncursesw config script missing: $NCURSES_BUILD/bin/ncursesw6-config" >&2
  exit 1
fi

ABS_SRC_DIR="$(cd "$SRC_DIR" && pwd)"
BUILD_DIR="$ABS_SRC_DIR/src"
BUILD_BIN="$BUILD_DIR/vim"
CC_WRAPPER="$ABS_SRC_DIR/build-musl-zigcc-wrapper.sh"

prepare_zig_wrapper() {
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

configure_vim() {
  prepare_zig_wrapper

  export ZIG_GLOBAL_CACHE_DIR="$REPO_ROOT/build/zig-global-cache"
  export ZIG_LOCAL_CACHE_DIR="$REPO_ROOT/build/zig-local-cache"
  mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"

  local ncurses_cflags
  local ncurses_libs
  ncurses_cflags="$("$NCURSES_CONFIG" --cflags)"
  ncurses_libs="$("$NCURSES_CONFIG" --libs)"

  pushd "$ABS_SRC_DIR" >/dev/null
  make -C src distclean >/dev/null 2>&1 || true
  # VibeOS has setitimer/SIGALRM, but not the POSIX timer/thread path Vim probes on the host.
  PKG_CONFIG=/bin/false \
  vim_cv_uname_output=Linux \
  vim_cv_uname_m_output=x86_64 \
  vim_cv_toupper_broken=no \
  vim_cv_terminfo=yes \
  vim_cv_tgetent=zero \
  vim_cv_getcwd_broken=no \
  vim_cv_timer_create=no \
  vim_cv_timer_create_with_lrt=no \
  vim_cv_timer_create_works=no \
  vim_cv_stat_ignores_slash=yes \
  vim_cv_memmove_handles_overlap=yes \
  ./configure \
    --prefix=/usr \
    --host=x86_64-linux-musl \
    --with-features=normal \
    --with-tlib=ncursesw \
    --without-x \
    --disable-gui \
    --disable-nls \
    --disable-acl \
    --disable-gpm \
    --disable-sysmouse \
    --disable-canberra \
    --disable-libsodium \
    --disable-netbeans \
    --disable-channel \
    --disable-terminal \
    --disable-xsmp \
    --disable-xsmp-interact \
    CC="$CC_WRAPPER" \
    HOSTCC="${HOSTCC:-cc}" \
    AR="zig ar" \
    RANLIB="zig ranlib" \
    CPPFLAGS="$ncurses_cflags" \
    CFLAGS="-Os -fno-stack-protector -fomit-frame-pointer -fno-pie" \
    LDFLAGS="-static -no-pie -L$ABS_NCURSES_BUILD/lib" \
    LIBS="$ncurses_libs" \
    2>&1 | tee "$ABS_SRC_DIR/build-musl-configure.log" || {
      echo "Configure failed. Check $ABS_SRC_DIR/build-musl-configure.log" >&2
      exit 1
    }
  popd >/dev/null
}

build_vim() {
  local ncurses_libs
  ncurses_libs="$("$NCURSES_CONFIG" --libs)"

  pushd "$BUILD_DIR" >/dev/null
  make -j1 vim \
    CC="$CC_WRAPPER" \
    AR="zig ar" \
    RANLIB="zig ranlib" \
    CFLAGS="-Os -fno-stack-protector -fomit-frame-pointer -fno-pie" \
    LDFLAGS="-static -no-pie -L$ABS_NCURSES_BUILD/lib" \
    LIBS="$ncurses_libs" \
    2>&1 | tee "$ABS_SRC_DIR/build-musl-build.log" || {
      echo "Build failed. Check $ABS_SRC_DIR/build-musl-build.log" >&2
      exit 1
    }
  popd >/dev/null
}

validate_binary() {
  local bin="$1"
  if [[ ! -x "$bin" ]]; then
    echo "Vim binary is not executable: $bin" >&2
    return 1
  fi

  if ! readelf -h "$bin" | grep -q "Machine:[[:space:]]*Advanced Micro Devices X86-64"; then
    echo "Vim is not amd64: $bin" >&2
    return 1
  fi

  if ! readelf -h "$bin" | grep -q "Type:[[:space:]]*EXEC"; then
    echo "Vim must be non-PIE ET_EXEC for current loader: $bin" >&2
    return 1
  fi

  if readelf -l "$bin" | grep -q "Requesting program interpreter"; then
    echo "Vim must be static (no PT_INTERP): $bin" >&2
    return 1
  fi
}

stage_vim() {
  rm -rf "$OUT_TREE"
  mkdir -p "$OUT_TREE/bin" "$OUT_TREE/share/vim"

  cp "$BUILD_BIN" "$OUT_TREE/bin/vim"
  chmod +x "$OUT_TREE/bin/vim"
  maybe_strip_binary "$OUT_TREE/bin/vim"

  cp -a "$ABS_SRC_DIR/runtime" "$OUT_TREE/share/vim/vim91"
  rm -rf "$OUT_TREE/share/vim/vim91/doc/tags" \
         "$OUT_TREE/share/vim/vim91/spell" \
         "$OUT_TREE/share/vim/vim91/tutor" \
         "$OUT_TREE/share/vim/vim91/bitmaps" \
         "$OUT_TREE/share/vim/vim91/icons" \
         "$OUT_TREE/share/vim/vim91/lang" \
         "$OUT_TREE/share/vim/vim91/print" \
         "$OUT_TREE/share/vim/vim91/tools"
  find "$OUT_TREE/share/vim/vim91" -type d -name testdir -prune -exec rm -rf {} +
  find "$OUT_TREE/share/vim/vim91" -maxdepth 1 -type f \( \
    -name 'gvim*' -o \
    -name '*.desktop' -o \
    -name '*.gif' -o \
    -name '*.png' -o \
    -name '*.xpm' -o \
    -name '*.svg' -o \
    -name '*.pdf' -o \
    -name '*.eps' -o \
    -name '*.cdr' \
  \) -delete
  ln -s vim "$OUT_TREE/bin/vi"
  ln -s vim "$OUT_TREE/bin/view"
}

configure_vim
build_vim
validate_binary "$BUILD_BIN"
stage_vim

echo "Built Vim: $OUT_TREE"
