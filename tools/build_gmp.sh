#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <output-sysroot> <gmp-tarball>" >&2
  exit 1
fi

OUT_DIR="$1"
TARBALL="$2"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ ! -f "$TARBALL" ]]; then
  echo "GMP tarball not found: $TARBALL" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT_DIR")"
OUT_DIR="$(cd "$(dirname "$OUT_DIR")" && pwd)/$(basename "$OUT_DIR")"

BUILD_ROOT="$REPO_ROOT/build/deps/gmp"
SRC_DIR="$BUILD_ROOT/src"
BUILD_DIR="$BUILD_ROOT/build"
STAGE_DIR="$BUILD_ROOT/stage"
CC_WRAPPER="$BUILD_ROOT/zigcc-wrapper.sh"

prepare_zig_wrapper() {
  mkdir -p "$BUILD_ROOT"
  cat > "$CC_WRAPPER" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exec zig cc -target x86_64-linux-musl "$@"
EOF
  chmod +x "$CC_WRAPPER"
}

rm -rf "$BUILD_ROOT" "$OUT_DIR"
mkdir -p "$SRC_DIR" "$BUILD_DIR"
tar -xf "$TARBALL" -C "$SRC_DIR" --strip-components=1
prepare_zig_wrapper

export ZIG_GLOBAL_CACHE_DIR="$REPO_ROOT/build/zig-global-cache"
export ZIG_LOCAL_CACHE_DIR="$REPO_ROOT/build/zig-local-cache"
mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"

pushd "$BUILD_DIR" >/dev/null
"$SRC_DIR/configure" \
  --host=x86_64-linux-musl \
  --prefix=/usr \
  --disable-shared \
  --enable-static \
  --disable-cxx \
  --disable-assembly \
  CC="$CC_WRAPPER" \
  AR="zig ar" \
  RANLIB="zig ranlib" \
  CFLAGS="-Os -fno-stack-protector -fomit-frame-pointer -fno-pie" \
  LDFLAGS="-static -no-pie"

make -j1
make DESTDIR="$STAGE_DIR" install
popd >/dev/null

find "$STAGE_DIR/usr" -type f -name '*.la' -delete
find "$STAGE_DIR/usr" -type f -name '*.so*' -delete

if [[ ! -f "$STAGE_DIR/usr/include/gmp.h" || ! -f "$STAGE_DIR/usr/lib/libgmp.a" ]]; then
  echo "GMP install missing headers or static library" >&2
  exit 1
fi

zig ranlib "$STAGE_DIR/usr/lib/libgmp.a"
mv "$STAGE_DIR" "$OUT_DIR"

echo "Built GMP sysroot: $OUT_DIR"
