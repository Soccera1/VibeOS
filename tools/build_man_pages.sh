#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <output-dir> <man-pages-src-dir>" >&2
  exit 1
fi

OUT_DIR="$1"
SRC_DIR="$2"

if [[ ! -d "$SRC_DIR" ]]; then
  echo "man-pages source directory not found: $SRC_DIR" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT_DIR")"
OUT_DIR="$(cd "$(dirname "$OUT_DIR")" && pwd)/$(basename "$OUT_DIR")"
ABS_SRC_DIR="$(cd "$SRC_DIR" && pwd)"
STAGE_ROOT="${OUT_DIR}.stage"
DESTDIR_ROOT="$STAGE_ROOT/destdir"
TMP_ROOT="$ABS_SRC_DIR/.tmp"

cleanup() {
  rm -rf "$STAGE_ROOT" "$TMP_ROOT"
}
trap cleanup EXIT

rm -rf "$STAGE_ROOT"
mkdir -p "$DESTDIR_ROOT"

make -R -C "$ABS_SRC_DIR" GNUMAKEFLAGS= install-man prefix=/usr DESTDIR="$DESTDIR_ROOT" >/dev/null

if [[ ! -d "$DESTDIR_ROOT/usr/share/man" ]]; then
  echo "Installed man directory missing: $DESTDIR_ROOT/usr/share/man" >&2
  exit 1
fi

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"
cp -a "$DESTDIR_ROOT/usr/." "$OUT_DIR"/

find "$OUT_DIR" -type d -exec chmod 755 {} +
find "$OUT_DIR" -type f -exec chmod 644 {} +

echo "Staged man-pages tree: $OUT_DIR"
