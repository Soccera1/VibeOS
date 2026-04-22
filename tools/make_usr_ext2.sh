#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <output.ext2> [bash-bin] [help-bin] [sl-bin] [file-bin] [file-magic] [nano-bin] [coreutils-dir] [coreutils-programs]" >&2
  exit 1
fi

OUT_IMG="$1"
BASH_BIN="${2:-}"
HELP_BIN="${3:-}"
SL_BIN="${4:-}"
FILE_BIN="${5:-}"
FILE_MAGIC="${6:-}"
NANO_BIN="${7:-}"
COREUTILS_DIR="${8:-}"
COREUTILS_PROGS="${9:-}"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

ROOT="$WORKDIR/root"
mkdir -p "$ROOT"/{bin,share/misc,share/terminfo}

is_essential_coreutils_prog() {
  case "$1" in
    '['|basename|cat|chgrp|chmod|chown|cp|date|dd|df|dirname|echo|false|kill|ln|ls|mkdir|mkfifo|mknod|mv|pwd|readlink|rm|rmdir|sleep|stty|sync|test|touch|true|uname)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

install_coreutils_bins() {
  [[ -d "$COREUTILS_DIR" && -f "$COREUTILS_PROGS" ]] || return 0

  local src
  while IFS= read -r prog; do
    [[ -n "$prog" ]] || continue
    is_essential_coreutils_prog "$prog" && continue
    src="$COREUTILS_DIR/$prog"
    if [[ ! -x "$src" ]]; then
      echo "Missing coreutils binary: $src" >&2
      exit 1
    fi
    cp "$src" "$ROOT/bin/$prog"
    chmod +x "$ROOT/bin/$prog"
  done < "$COREUTILS_PROGS"
}

if [[ -d rootfs/usr ]]; then
  mkdir -p "$ROOT"
  cp -a rootfs/usr/. "$ROOT"/
fi

if [[ -n "$BASH_BIN" && -x "$BASH_BIN" ]]; then
  cp "$BASH_BIN" "$ROOT/bin/bash"
  chmod +x "$ROOT/bin/bash"
fi

if [[ -n "$HELP_BIN" && -x "$HELP_BIN" ]]; then
  cp "$HELP_BIN" "$ROOT/bin/help"
  chmod +x "$ROOT/bin/help"
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

install_coreutils_bins

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
