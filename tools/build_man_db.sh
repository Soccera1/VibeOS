#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 <output-tree> <man-db-src-dir> <libpipeline-sysroot> <groff-tree>" >&2
  exit 1
fi

OUT_DIR="$1"
SRC_DIR="$2"
LIBPIPELINE_SYSROOT="$3"
GROFF_TREE="$4"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/strip_helpers.sh"

if [[ ! -d "$SRC_DIR" ]]; then
  echo "man-db source directory not found: $SRC_DIR" >&2
  exit 1
fi
if [[ ! -d "$LIBPIPELINE_SYSROOT/usr/lib/pkgconfig" ]]; then
  echo "libpipeline sysroot missing pkg-config metadata: $LIBPIPELINE_SYSROOT" >&2
  exit 1
fi
if [[ ! -d "$GROFF_TREE/bin" ]]; then
  echo "groff tree missing bin directory: $GROFF_TREE" >&2
  exit 1
fi

ABS_SRC_DIR="$(cd "$SRC_DIR" && pwd)"
ABS_LIBPIPELINE_SYSROOT="$(cd "$LIBPIPELINE_SYSROOT" && pwd)"
ABS_GROFF_TREE="$(cd "$GROFF_TREE" && pwd)"
mkdir -p "$(dirname "$OUT_DIR")"
OUT_DIR="$(cd "$(dirname "$OUT_DIR")" && pwd)/$(basename "$OUT_DIR")"

BUILD_DIR="$ABS_SRC_DIR/build-musl"
STAGE_DIR="$BUILD_DIR/stage"
CC_WRAPPER="$BUILD_DIR/zigcc-wrapper.sh"
FAKE_GDBM_DIR="$BUILD_DIR/fake-gdbm"

prepare_zig_wrapper() {
  mkdir -p "$BUILD_DIR"
  cat > "$CC_WRAPPER" <<EOF
#!/usr/bin/env bash
set -euo pipefail

compiler="cc"
if [[ "\$(basename "\$0")" == *++* ]]; then
  compiler="c++"
fi

filtered=()
for arg in "\$@"; do
  case "\$arg" in
    -fuse-ld=*|--verbose|-static-libgcc|-static-libstdc++)
      continue
      ;;
  esac

  if [[ "\$arg" == -Wl,* ]]; then
    payload="\${arg#-Wl,}"
    IFS=',' read -r -a parts <<< "\$payload"
    kept=()
    drop_next=0
    for part in "\${parts[@]}"; do
      if (( drop_next )); then
        drop_next=0
        continue
      fi
      case "\$part" in
        -Map)
          drop_next=1
          continue
          ;;
        -Map=*|--warn-common|--sort-common|--warn-execstack|--warn-rwx-segments|--verbose)
          continue
          ;;
      esac
      kept+=("\$part")
    done
    if (( \${#kept[@]} > 0 )); then
      (IFS=','; filtered+=("-Wl,\${kept[*]}"))
    fi
    continue
  fi

  filtered+=("\$arg")
done

exec zig "\$compiler" -target x86_64-linux-musl "\${filtered[@]}"
EOF
  chmod +x "$CC_WRAPPER"
  ln -sf "$(basename "$CC_WRAPPER")" "$BUILD_DIR/zigcxx-wrapper.sh"
}

prepare_fake_gdbm() {
  local include_dir="$FAKE_GDBM_DIR/include"
  local lib_dir="$FAKE_GDBM_DIR/lib"
  local shim_c="$FAKE_GDBM_DIR/gdbm_shim.c"
  local shim_o="$FAKE_GDBM_DIR/gdbm_shim.o"

  rm -rf "$FAKE_GDBM_DIR"
  mkdir -p "$include_dir" "$lib_dir"

  cat > "$include_dir/gdbm.h" <<'EOF'
#ifndef _GDBM_H_
#define _GDBM_H_

#include <stdio.h>
#include <sys/types.h>

#define GDBM_READER 0
#define GDBM_WRITER 1
#define GDBM_WRCREAT 2
#define GDBM_NEWDB 3
#define GDBM_OPENMASK 7

#define GDBM_FAST 0x0010
#define GDBM_SYNC 0x0020
#define GDBM_NOLOCK 0x0040
#define GDBM_NOMMAP 0x0080

#define GDBM_INSERT 0
#define GDBM_REPLACE 1

typedef struct {
  char *dptr;
  int dsize;
} datum;

typedef struct gdbm_file_info *GDBM_FILE;

extern GDBM_FILE gdbm_open(const char *file, int block_size, int flags, int mode,
                           void (*fatal_func)(const char *));
extern int gdbm_close(GDBM_FILE dbf);
extern int gdbm_store(GDBM_FILE dbf, datum key, datum content, int flag);
extern datum gdbm_fetch(GDBM_FILE dbf, datum key);
extern int gdbm_delete(GDBM_FILE dbf, datum key);
extern datum gdbm_firstkey(GDBM_FILE dbf);
extern datum gdbm_nextkey(GDBM_FILE dbf, datum key);
extern int gdbm_exists(GDBM_FILE dbf, datum key);
extern int gdbm_fdesc(GDBM_FILE dbf);

#endif
EOF

  cat > "$shim_c" <<'EOF'
#include <stdlib.h>

#include "gdbm.h"

struct gdbm_file_info {
  int unused;
};

static datum empty_datum(void) {
  datum value;

  value.dptr = NULL;
  value.dsize = 0;
  return value;
}

GDBM_FILE gdbm_open(const char *file, int block_size, int flags, int mode,
                    void (*fatal_func)(const char *)) {
  (void)file;
  (void)block_size;
  (void)flags;
  (void)mode;
  (void)fatal_func;
  return NULL;
}

int gdbm_close(GDBM_FILE dbf) {
  (void)dbf;
  return 0;
}

int gdbm_store(GDBM_FILE dbf, datum key, datum content, int flag) {
  (void)dbf;
  (void)key;
  (void)content;
  (void)flag;
  return -1;
}

datum gdbm_fetch(GDBM_FILE dbf, datum key) {
  (void)dbf;
  (void)key;
  return empty_datum();
}

int gdbm_delete(GDBM_FILE dbf, datum key) {
  (void)dbf;
  (void)key;
  return -1;
}

datum gdbm_firstkey(GDBM_FILE dbf) {
  (void)dbf;
  return empty_datum();
}

datum gdbm_nextkey(GDBM_FILE dbf, datum key) {
  (void)dbf;
  (void)key;
  return empty_datum();
}

int gdbm_exists(GDBM_FILE dbf, datum key) {
  (void)dbf;
  (void)key;
  return 0;
}

int gdbm_fdesc(GDBM_FILE dbf) {
  (void)dbf;
  return -1;
}
EOF

  zig cc -target x86_64-linux-musl \
    -Os \
    -fno-stack-protector \
    -fomit-frame-pointer \
    -fno-pie \
    -I"$include_dir" \
    -c "$shim_c" \
    -o "$shim_o"
  zig ar rcs "$lib_dir/libgdbm.a" "$shim_o"
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
DEFINE		pager		cat
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

  prepare_zig_wrapper
  prepare_fake_gdbm

  pushd "$BUILD_DIR" >/dev/null
  PATH="$ABS_GROFF_TREE/bin:$PATH" \
  PKG_CONFIG_PATH="$ABS_LIBPIPELINE_SYSROOT/usr/lib/pkgconfig" \
  PKG_CONFIG_SYSROOT_DIR="$ABS_LIBPIPELINE_SYSROOT" \
  "$ABS_SRC_DIR/configure" \
    --prefix=/usr \
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
    AR="zig ar" \
    RANLIB="zig ranlib" \
    CPPFLAGS="-I$FAKE_GDBM_DIR/include" \
    CFLAGS="-Os -fno-stack-protector -fomit-frame-pointer -fno-pie" \
    LDFLAGS="-static -no-pie -L$FAKE_GDBM_DIR/lib" \
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
  rm -rf "$OUT_DIR/lib"
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
