#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/strip_helpers.sh"

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <output.ext3> [bash-bin] [help-bin] [sl-bin] [file-bin] [file-magic] [nano-bin] [less-bin] [coreutils-dir] [coreutils-programs] [usr-tree...]" >&2
  exit 1
fi

OUT_IMG="$1"
BASH_BIN="${2:-}"
HELP_BIN="${3:-}"
SL_BIN="${4:-}"
FILE_BIN="${5:-}"
FILE_MAGIC="${6:-}"
NANO_BIN="${7:-}"
LESS_BIN="${8:-}"
COREUTILS_DIR="${9:-}"
COREUTILS_PROGS="${10:-}"
if [[ $# -gt 10 ]]; then
  shift 10
else
  shift $#
fi
USR_TREES=("$@")

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

if [[ -n "$LESS_BIN" && -x "$LESS_BIN" ]]; then
  cp "$LESS_BIN" "$ROOT/bin/less"
  chmod +x "$ROOT/bin/less"
fi

for usr_tree in "${USR_TREES[@]}"; do
  [[ -n "$usr_tree" && -d "$usr_tree" ]] || continue
  cp -a "$usr_tree"/. "$ROOT"/
done

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

maybe_strip_tree_binaries "$ROOT"

mkdir -p "$(dirname "$OUT_IMG")"

BLOCK_SIZE=4096
INODE_SIZE=256

count_root_inodes() {
  find "$ROOT" -printf '.' | wc -c
}

estimate_data_blocks() {
  find "$ROOT" -printf '%y %s\n' | awk -v block_size="$BLOCK_SIZE" '
    $1 == "d" {
      blocks += 1
      next
    }
    $1 == "f" {
      blocks += int(($2 + block_size - 1) / block_size)
      next
    }
    $1 == "l" {
      if ($2 > 60) {
        blocks += int(($2 + block_size - 1) / block_size)
      }
      next
    }
    END {
      if (blocks < 1) {
        blocks = 1
      }
      print blocks
    }
  '
}

build_ext3_image() {
  local image="$1"
  local blocks="$2"

  rm -f "$image"
  mkfs.ext3 -q -F \
    -b "$BLOCK_SIZE" \
    -m 0 \
    -N "$INODE_COUNT" \
    -O ^dir_index \
    -L VIBEUSR \
    -d "$ROOT" \
    "$image" "$blocks" >/dev/null 2>&1
}

INODE_COUNT="$(count_root_inodes)"
if [[ -z "$INODE_COUNT" || "$INODE_COUNT" -lt 1 ]]; then
  INODE_COUNT=1
fi

DATA_BLOCKS="$(estimate_data_blocks)"
INODE_TABLE_BLOCKS=$(( (INODE_COUNT * INODE_SIZE + BLOCK_SIZE - 1) / BLOCK_SIZE ))
LOWER_BLOCKS=$(( DATA_BLOCKS + INODE_TABLE_BLOCKS + 8 ))
if (( LOWER_BLOCKS < 16 )); then
  LOWER_BLOCKS=16
fi

TMP_IMG="$WORKDIR/usr.ext3"
UPPER_BLOCKS="$LOWER_BLOCKS"
until build_ext3_image "$TMP_IMG" "$UPPER_BLOCKS"; do
  UPPER_BLOCKS=$(( UPPER_BLOCKS * 2 ))
done

while (( LOWER_BLOCKS < UPPER_BLOCKS )); do
  MID_BLOCKS=$(( (LOWER_BLOCKS + UPPER_BLOCKS) / 2 ))
  if build_ext3_image "$TMP_IMG" "$MID_BLOCKS"; then
    UPPER_BLOCKS="$MID_BLOCKS"
  else
    LOWER_BLOCKS=$(( MID_BLOCKS + 1 ))
  fi
done

build_ext3_image "$OUT_IMG" "$LOWER_BLOCKS" || {
  echo "Failed to build ext3 image with $LOWER_BLOCKS blocks" >&2
  exit 1
}
