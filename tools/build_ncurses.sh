#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <output-lib> <ncurses-src-dir>" >&2
  exit 1
fi

OUT_LIB="$1"
SRC_DIR="$2"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/musl_toolchain.sh"
musl_init
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

mkdir -p "$(dirname "$OUT_LIB")"

NCURSES_BUILD="$(cd "$SRC_DIR" && pwd)/build-musl"
musl_prepare_cached_build "$NCURSES_BUILD" "$SRC_DIR"
NCURSES_TERMINFO_INSTALL="$NCURSES_BUILD/share/terminfo"

if [[ ! -f "$NCURSES_BUILD/lib/libncurses.a" ]]; then
  mkdir -p "$NCURSES_BUILD"

  export ZIG_GLOBAL_CACHE_DIR="$REPO_ROOT/build/zig-global-cache"
  export ZIG_LOCAL_CACHE_DIR="$REPO_ROOT/build/zig-local-cache"
  mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"

  CC_WRAPPER="$NCURSES_BUILD/muslcc-wrapper.sh"
  musl_write_wrapper "$CC_WRAPPER" cc terminal
  chmod +x "$CC_WRAPPER"

  pushd "$SRC_DIR" >/dev/null

  env -u TERMINFO -u TERMINFO_DIRS \
  ./configure \
    --prefix="$NCURSES_BUILD" \
    --with-default-terminfo-dir=/usr/share/terminfo \
    --with-terminfo-dirs=/usr/share/terminfo:/lib/terminfo:/usr/local/share/terminfo \
    --with-default-terminfo-paths=/usr/share/terminfo:/lib/terminfo:/usr/local/share/terminfo \
    --disable-shared \
    --without-shared \
    --without-cxx \
    --without-cxx-binding \
    --without-ada \
    --without-manpages \
    --without-progs \
    --without-tests \
    --without-debug \
    --without-profile \
    --disable-home-terminfo \
    --enable-const \
    --enable-widec \
    --disable-ext-colors \
    --disable-ext-mouse \
    --disable-termcap \
    --disable-tic-deps \
    --with-termlib \
    --with-ticlib \
    --host=x86_64-linux-musl \
    CC="$CC_WRAPPER" \
    HOSTCC="${HOSTCC:-cc}" \
    BUILD_CC="${BUILD_CC:-cc}" \
    AR="$MUSL_AR" \
    RANLIB="$MUSL_RANLIB" \
    CPPFLAGS="-DNOMACROS=1" \
    CFLAGS="-Os -fno-stack-protector -fomit-frame-pointer -fno-exceptions -fno-asynchronous-unwind-tables" \
    BUILD_CFLAGS="-Os" \
    LDFLAGS="-static" \
    ac_cv_func_getopt=yes \
    ac_cv_func_getopt_long=yes \
    ac_cv_func_vsnprintf=yes \
    ac_cv_func_snprintf=yes \
    ac_cv_func_sprintf=yes \
    ac_cv_func_sscanf=yes \
    2>&1 | tee "$NCURSES_BUILD/configure.log" || {
      echo "Configure failed. Check $NCURSES_BUILD/configure.log" >&2
      exit 1
    }

  make -j"$(nproc)" 2>&1 | tee "$NCURSES_BUILD/build.log" || {
    echo "Make failed. Check $NCURSES_BUILD/build.log" >&2
    exit 1
  }

  make install ticdir="$NCURSES_TERMINFO_INSTALL" 2>&1 | tee -a "$NCURSES_BUILD/build.log" || {
    echo "Make install failed." >&2
    exit 1
  }

  popd >/dev/null
fi

if [[ ! "$NCURSES_BUILD/lib/libncursesw.a" -ef "$OUT_LIB" ]]; then
  cp "$NCURSES_BUILD/lib/libncursesw.a" "$OUT_LIB"
fi
echo "Built ncurses: $OUT_LIB"

musl_fingerprint > "$NCURSES_BUILD/.musl-toolchain"
