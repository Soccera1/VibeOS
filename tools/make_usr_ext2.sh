#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <output.ext2> [sl-bin] [file-bin] [file-magic] [nano-bin]" >&2
  exit 1
fi

OUT_IMG="$1"
SL_BIN="${2:-}"
FILE_BIN="${3:-}"
FILE_MAGIC="${4:-}"
NANO_BIN="${5:-}"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

ROOT="$WORKDIR/root"
mkdir -p "$ROOT"/{bin,share/misc,share/terminfo}

if [[ -d rootfs/usr ]]; then
  mkdir -p "$ROOT"
  cp -a rootfs/usr/. "$ROOT"/
fi

if [[ -n "$SL_BIN" && -x "$SL_BIN" ]]; then
  cp "$SL_BIN" "$ROOT/bin/sl"
  chmod +x "$ROOT/bin/sl"
fi

if [[ -n "$FILE_BIN" && -x "$FILE_BIN" ]]; then
  cp "$FILE_BIN" "$ROOT/bin/file"
  chmod +x "$ROOT/bin/file"
fi

if [[ -n "$FILE_MAGIC" && -f "$FILE_MAGIC" ]]; then
  mkdir -p "$ROOT/share/misc"
  cp "$FILE_MAGIC" "$ROOT/share/misc/magic.mgc"
fi

if [[ -n "$NANO_BIN" && -x "$NANO_BIN" ]]; then
  cp "$NANO_BIN" "$ROOT/bin/nano"
  chmod +x "$ROOT/bin/nano"
fi

copy_terminfo() {
  local entry="$1"
  local src="external/ncurses-src/build-musl/share/terminfo/${entry:0:1}/$entry"
  local dst="$ROOT/share/terminfo/${entry:0:1}/$entry"
  if [[ -f "$src" ]]; then
    mkdir -p "$(dirname "$dst")"
    cp "$src" "$dst"
  fi
}

copy_terminfo linux
copy_terminfo vt100
copy_terminfo xterm
copy_terminfo ansi
copy_terminfo dumb

mkdir -p "$(dirname "$OUT_IMG")"

ROOT_KIB="$(du -sk "$ROOT" | awk '{print $1}')"
if [[ -z "$ROOT_KIB" || "$ROOT_KIB" -lt 1 ]]; then
  ROOT_KIB=1
fi

IMG_KIB=$(( ROOT_KIB + ROOT_KIB / 2 + 16384 ))
if (( IMG_KIB < 16384 )); then
  IMG_KIB=16384
fi

truncate -s "${IMG_KIB}K" "$OUT_IMG"
mkfs.ext2 -q -F -b 4096 -L VIBEUSR -d "$ROOT" "$OUT_IMG"
