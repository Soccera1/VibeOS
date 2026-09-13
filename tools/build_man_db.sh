#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo "usage: $0 <output-tree> <man-db-src-dir> <libpipeline-sysroot> <gdbm-sysroot> <groff-tree>" >&2
  exit 1
fi

OUT_DIR="$1"
SRC_DIR="$2"
LIBPIPELINE_SYSROOT="$3"
GDBM_SYSROOT="$4"
GROFF_TREE="$5"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/musl_toolchain.sh"
musl_init
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/strip_helpers.sh"

if [[ ! -d "$SRC_DIR" ]]; then
  echo "man-db source directory not found: $SRC_DIR" >&2
  exit 1
fi
LIBPIPELINE_PKGCONFIG_DIR=""
if [[ -d "$LIBPIPELINE_SYSROOT/usr/lib64/pkgconfig" ]]; then
  LIBPIPELINE_PKGCONFIG_DIR="$LIBPIPELINE_SYSROOT/usr/lib64/pkgconfig"
elif [[ -d "$LIBPIPELINE_SYSROOT/usr/lib/pkgconfig" ]]; then
  LIBPIPELINE_PKGCONFIG_DIR="$LIBPIPELINE_SYSROOT/usr/lib/pkgconfig"
fi
if [[ -z "$LIBPIPELINE_PKGCONFIG_DIR" ]]; then
  echo "libpipeline sysroot missing pkg-config metadata: $LIBPIPELINE_SYSROOT" >&2
  exit 1
fi
GDBM_LIB_DIR=""
if [[ -f "$GDBM_SYSROOT/usr/lib64/libgdbm.a" ]]; then
  GDBM_LIB_DIR="$GDBM_SYSROOT/usr/lib64"
elif [[ -f "$GDBM_SYSROOT/usr/lib/libgdbm.a" ]]; then
  GDBM_LIB_DIR="$GDBM_SYSROOT/usr/lib"
fi
if [[ ! -f "$GDBM_SYSROOT/usr/include/gdbm.h" || -z "$GDBM_LIB_DIR" ]]; then
  echo "gdbm sysroot missing static library or headers: $GDBM_SYSROOT" >&2
  exit 1
fi
if [[ ! -d "$GROFF_TREE/bin" ]]; then
  echo "groff tree missing bin directory: $GROFF_TREE" >&2
  exit 1
fi

ABS_SRC_DIR="$(cd "$SRC_DIR" && pwd)"
ABS_LIBPIPELINE_SYSROOT="$(cd "$LIBPIPELINE_SYSROOT" && pwd)"
ABS_LIBPIPELINE_PKGCONFIG_DIR="$(cd "$LIBPIPELINE_PKGCONFIG_DIR" && pwd)"
ABS_GDBM_SYSROOT="$(cd "$GDBM_SYSROOT" && pwd)"
ABS_GDBM_LIB_DIR="$(cd "$GDBM_LIB_DIR" && pwd)"
ABS_GROFF_TREE="$(cd "$GROFF_TREE" && pwd)"
mkdir -p "$(dirname "$OUT_DIR")"
OUT_DIR="$(cd "$(dirname "$OUT_DIR")" && pwd)/$(basename "$OUT_DIR")"

BUILD_DIR="$ABS_SRC_DIR/build-musl"
STAGE_DIR="$BUILD_DIR/stage"
CC_WRAPPER="$BUILD_DIR/muslcc-wrapper.sh"

prepare_musl_wrapper() {
  mkdir -p "$BUILD_DIR"
  musl_write_wrapper "$CC_WRAPPER" cc standard
  chmod +x "$CC_WRAPPER"
}

write_config() {
  local cfg="$1"
  cat > "$cfg" <<'EOF'
# man_db.conf
MANDATORY_MANPATH	/usr/share/man
MANPATH_MAP	/bin		/usr/share/man
MANPATH_MAP	/usr/bin	/usr/share/man
MANPATH_MAP	/usr/sbin	/usr/share/man
MANDB_MAP	/usr/share/man	/tmp/man
SECTION		1 n l 8 3 0 2 3type 5 4 9 6 7
# The console supports normal forward and reverse scrolling.  Keep short
# movements incremental; zero scroll limits force a full-screen repaint.
DEFINE		pager		env TERMINFO=/usr/terminfo TERM=vibeos less -h10 -y10
DEFINE		cat		cat
DEFINE		nroff		groff -mandoc -mtty-char
DEFINE		troff		groff
DEFINE		eqn		eqn
DEFINE		neqn		neqn
DEFINE		tbl		tbl
DEFINE		col		col
DEFINE		refer		refer
DEFINE		pic		pic
NOCACHE
EOF
}

configure_man_db() {
  rm -rf "$BUILD_DIR"
  mkdir -p "$BUILD_DIR"

  export ZIG_GLOBAL_CACHE_DIR="$REPO_ROOT/build/zig-global-cache"
  export ZIG_LOCAL_CACHE_DIR="$REPO_ROOT/build/zig-local-cache"
  mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"

  prepare_musl_wrapper

  pushd "$BUILD_DIR" >/dev/null
  PATH="$ABS_GROFF_TREE/bin:$PATH" \
  PKG_CONFIG_PATH="$ABS_LIBPIPELINE_PKGCONFIG_DIR" \
  PKG_CONFIG_SYSROOT_DIR="$ABS_LIBPIPELINE_SYSROOT" \
  "$ABS_SRC_DIR/configure" \
    --prefix=/usr \
    --libdir=/usr/lib64 \
    --sysconfdir=/usr/etc \
    --with-db=gdbm \
    --without-libseccomp \
    --disable-shared \
    --enable-static \
    --disable-setuid \
    --disable-cache-owner \
    --disable-automatic-create \
    --disable-automatic-update \
    --disable-cats \
    --disable-nls \
    --disable-manual \
    --with-systemdtmpfilesdir=no \
    --with-systemdsystemunitdir=no \
    --with-config-file='${sysconfdir}/man_db.conf' \
    CC="$CC_WRAPPER" \
    CPP="$CC_WRAPPER -E" \
    AR="$MUSL_AR" \
    RANLIB="$MUSL_RANLIB" \
    CPPFLAGS="-I$ABS_GDBM_SYSROOT/usr/include" \
    CFLAGS="-Os -fno-stack-protector -fomit-frame-pointer -fno-pie" \
    LDFLAGS="-static -no-pie -L$ABS_GDBM_LIB_DIR" \
    2>&1 | tee configure.log || {
      echo "Configure failed. Check $BUILD_DIR/configure.log" >&2
      exit 1
    }
  popd >/dev/null
}

build_man_db() {
  pushd "$BUILD_DIR" >/dev/null
  PATH="$ABS_GROFF_TREE/bin:$PATH" \
  make -j1 2>&1 | tee build.log || {
    echo "Build failed. Check $BUILD_DIR/build.log" >&2
    exit 1
  }
  popd >/dev/null
}

validate_binary() {
  local bin="$1"
  [[ -x "$bin" ]] || return 1
  readelf -h "$bin" | grep -q "Machine:[[:space:]]*Advanced Micro Devices X86-64" || return 1
  readelf -h "$bin" | grep -q "Type:[[:space:]]*EXEC" || return 1
  ! readelf -l "$bin" | grep -q "Requesting program interpreter"
}

stage_man_db() {
  rm -rf "$STAGE_DIR" "$OUT_DIR"
  mkdir -p "$STAGE_DIR"

  pushd "$BUILD_DIR" >/dev/null
  make -j1 install DESTDIR="$STAGE_DIR" 2>&1 | tee install.log || {
    echo "Install failed. Check $BUILD_DIR/install.log" >&2
    exit 1
  }
  popd >/dev/null

  validate_binary "$STAGE_DIR/usr/bin/man" || {
    echo "Installed man binary failed validation" >&2
    exit 1
  }

  mkdir -p "$OUT_DIR" "$OUT_DIR/etc"
  cp -a "$STAGE_DIR/usr/." "$OUT_DIR"/
  mkdir -p "$OUT_DIR/lib"
  rm -f \
    "$OUT_DIR/bin/apropos" \
    "$OUT_DIR/bin/catman" \
    "$OUT_DIR/bin/mandb" \
    "$OUT_DIR/bin/whatis" \
    "$OUT_DIR/sbin/accessdb" \
    "$OUT_DIR/share/man/man1/apropos.1" \
    "$OUT_DIR/share/man/man1/whatis.1" \
    "$OUT_DIR/share/man/man8/accessdb.8" \
    "$OUT_DIR/share/man/man8/catman.8" \
    "$OUT_DIR/share/man/man8/mandb.8"
  write_config "$OUT_DIR/etc/man_db.conf"
  maybe_strip_tree_binaries "$OUT_DIR"
}

configure_man_db
build_man_db
stage_man_db

echo "Built man-db tree: $OUT_DIR"
