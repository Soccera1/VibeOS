#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <output-bin> <sl-src-dir> <ncurses-build-dir>" >&2
  exit 1
fi

OUT_BIN="$1"
SRC_DIR="$2"
NCURSES_BUILD="$3"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/strip_helpers.sh"

mkdir -p "$(dirname "$OUT_BIN")"

if [[ -f "$NCURSES_BUILD/include/ncursesw/ncurses.h" ]]; then
  NCURSES_INC="$NCURSES_BUILD/include/ncursesw"
elif [[ -f "$NCURSES_BUILD/include/ncurses.h" ]]; then
  NCURSES_INC="$NCURSES_BUILD/include"
else
  echo "ncurses.h not found; run build_ncurses.sh first" >&2
  exit 1
fi

if [[ -f "$NCURSES_BUILD/lib/libncursesw.a" ]]; then
  NCURSES_LIB="$NCURSES_BUILD/lib/libncursesw.a"
elif [[ -f "$NCURSES_BUILD/lib/libncurses.a" ]]; then
  NCURSES_LIB="$NCURSES_BUILD/lib/libncurses.a"
else
  echo "libncursesw.a or libncurses.a not found; run build_ncurses.sh first" >&2
  exit 1
fi

NCURSES_LIBDIR="$(dirname "$NCURSES_LIB")"

echo "Building sl from $SRC_DIR"

NCURSES_LIBDIR_ABS="$(cd "$NCURSES_LIBDIR" && pwd)"
NCURSES_INC_ABS="$(cd "$NCURSES_INC" && pwd)"

CC_WRAPPER="$REPO_ROOT/build/sl-wrapper.sh"
mkdir -p "$(dirname "$CC_WRAPPER")"
cat > "$CC_WRAPPER" <<WRAPPER_EOF
#!/usr/bin/env bash
set -euo pipefail
filtered=()
for arg in "\$@"; do
  case "\$arg" in
    -Wl,-rpath*|-Wl,--rpath*|-Wl,-soname*|-Wl,--soname*|-Wl,--version-script*|-lncurses)
      continue
      ;;
  esac
  filtered+=("\$arg")
done
exec zig cc -target x86_64-linux-musl "\${filtered[@]}" -L$NCURSES_LIBDIR_ABS -lncursesw -ltinfow
WRAPPER_EOF
chmod +x "$CC_WRAPPER"

pushd "$SRC_DIR" >/dev/null

rm -f sl

"$CC_WRAPPER" -Os -fno-stack-protector -fomit-frame-pointer -DNCURSES_WIDECHAR -I"$NCURSES_INC_ABS/.." -I"$NCURSES_INC_ABS" -static -o sl sl.c 2>&1 || {
  echo "Build failed" >&2
  exit 1
}

popd >/dev/null

cp "$SRC_DIR/sl" "$OUT_BIN"
chmod +x "$OUT_BIN"
maybe_strip_binary "$OUT_BIN"

if readelf -h "$OUT_BIN" 2>/dev/null | grep -q "Type:.*EXEC"; then
  echo "Built sl (static ELF): $OUT_BIN"
else
  echo "Warning: sl may not be static ET_EXEC" >&2
fi
