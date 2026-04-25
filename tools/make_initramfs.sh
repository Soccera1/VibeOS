#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/strip_helpers.sh"

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <output.cpio> <busybox-bin> [help-bin] [coreutils-dir] [coreutils-programs]" >&2
  exit 1
fi

OUT_CPIO_INPUT="$1"
OUT_CPIO_DIR="$(cd "$(dirname "$OUT_CPIO_INPUT")" && pwd)"
OUT_CPIO="$OUT_CPIO_DIR/$(basename "$OUT_CPIO_INPUT")"
BUSYBOX_BIN="$2"
HELP_BIN="${3:-}"
COREUTILS_DIR="${4:-}"
COREUTILS_PROGS="${5:-}"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

ROOT="$WORKDIR/root"
mkdir -p "$ROOT"/{bin,dev,etc,proc,sys,tmp,usr,var,home}

is_coreutils_prog() {
  local prog="$1"
  [[ -n "$COREUTILS_PROGS" && -f "$COREUTILS_PROGS" ]] || return 1
  grep -Fxq "$prog" "$COREUTILS_PROGS"
}

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
    is_essential_coreutils_prog "$prog" || continue
    src="$COREUTILS_DIR/$prog"
    if [[ ! -x "$src" ]]; then
      echo "Missing coreutils binary: $src" >&2
      exit 1
    fi
    cp "$src" "$ROOT/bin/$prog"
    chmod +x "$ROOT/bin/$prog"
  done < "$COREUTILS_PROGS"
}

if [[ -d rootfs ]]; then
  pushd rootfs >/dev/null
  find . -mindepth 1 \
    ! -path './bin/busybox' \
    ! -path './bin/bash' \
    ! -path './bin/help' \
    ! -path './usr' \
    ! -path './usr/*' \
    -print0 | cpio --null -pdm "$ROOT" >/dev/null 2>&1 || true
  popd >/dev/null
fi

if [[ -x "$BUSYBOX_BIN" ]]; then
  cp "$BUSYBOX_BIN" "$ROOT/bin/busybox"
elif [[ -x rootfs/bin/busybox ]]; then
  cp rootfs/bin/busybox "$ROOT/bin/busybox"
elif [[ -x external/busybox-static ]]; then
  cp external/busybox-static "$ROOT/bin/busybox"
else
  echo "BusyBox binary missing: $BUSYBOX_BIN" >&2
  exit 1
fi

chmod +x "$ROOT/bin/busybox"
maybe_strip_binary "$ROOT/bin/busybox"
ln -sf /usr/bin/bash "$ROOT/bin/bash"
install_coreutils_bins
maybe_strip_tree_binaries "$ROOT"

is_blocked_applet() {
  is_coreutils_prog "$1"
}

if APPLETS="$("$ROOT/bin/busybox" --list-full 2>/dev/null)"; then
  while IFS= read -r app; do
    [[ -z "$app" ]] && continue
    rel="/$app"
    base="${app##*/}"
    is_blocked_applet "$base" && continue
    [[ "$rel" == "/bin/busybox" ]] && continue
    [[ "$rel" == "/usr/"* ]] && continue
    mkdir -p "$ROOT$(dirname "$rel")"
    ln -sf /bin/busybox "$ROOT$rel"
  done <<< "$APPLETS"
elif APPLETS="$("$ROOT/bin/busybox" --list 2>/dev/null)"; then
  while IFS= read -r app; do
    [[ -z "$app" || "$app" == "busybox" ]] && continue
    is_blocked_applet "$app" && continue
    ln -sf /bin/busybox "$ROOT/bin/$app"
  done <<< "$APPLETS"
else
  echo "warning: failed to enumerate BusyBox applets, using minimal fallback links" >&2
  for app in sh ash hush ls cat echo uname clear pwd cd; do
    ln -sf /bin/busybox "$ROOT/bin/$app"
  done
fi

cat > "$ROOT/etc/motd" <<'MOTD'
VibeOS monolithic kernel prototype
Type: help
MOTD

cat > "$ROOT/.bashrc" <<'BASHRC'
if command -v dircolors >/dev/null 2>&1; then
  eval "$(dircolors -b)"
fi

if ls --color=auto / >/dev/null 2>&1; then
  alias ls='ls --color=auto'
fi

if grep --color=auto "" /dev/null >/dev/null 2>&1; then
  alias grep='grep --color=auto'
fi

if command -v diff >/dev/null 2>&1 && diff --color=auto /dev/null /dev/null >/dev/null 2>&1; then
  alias diff='diff --color=auto'
fi
BASHRC
if [[ -n "$HELP_BIN" && -x "$HELP_BIN" ]]; then
  cat >> "$ROOT/.bashrc" <<'BASHRC'
alias help='/usr/bin/help'
BASHRC
fi

cat > "$ROOT/init" <<'INIT'
#!/bin/busybox sh
while true; do
  if [ -x /usr/bin/bash ]; then
    /usr/bin/bash -i
  else
    /bin/busybox sh -i
  fi
done
INIT
chmod +x "$ROOT/init"

pushd "$ROOT" >/dev/null
find . -print0 | cpio --null -o --format=newc > "$OUT_CPIO"
popd >/dev/null
