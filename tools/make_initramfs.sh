#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <output.cpio> <busybox-bin> [bash-bin] [sl-bin] [help-bin] [file-bin] [file-magic] [nano-bin]" >&2
  exit 1
fi

OUT_CPIO_INPUT="$1"
OUT_CPIO_DIR="$(cd "$(dirname "$OUT_CPIO_INPUT")" && pwd)"
OUT_CPIO="$OUT_CPIO_DIR/$(basename "$OUT_CPIO_INPUT")"
BUSYBOX_BIN="$2"
BASH_BIN="${3:-}"
SL_BIN="${4:-}"
HELP_BIN="${5:-}"
FILE_BIN="${6:-}"
FILE_MAGIC="${7:-}"
NANO_BIN="${8:-}"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

ROOT="$WORKDIR/root"
mkdir -p "$ROOT"/{bin,dev,etc,proc,sys,tmp,usr,var,home}

if [[ -d rootfs ]]; then
  pushd rootfs >/dev/null
  find . -mindepth 1 ! -path './bin/busybox' ! -path './usr' ! -path './usr/*' -print0 | cpio --null -pdm "$ROOT" >/dev/null 2>&1 || true
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

if [[ -n "$BASH_BIN" && -x "$BASH_BIN" ]]; then
  cp "$BASH_BIN" "$ROOT/bin/bash"
fi

if [[ -n "$HELP_BIN" && -x "$HELP_BIN" ]]; then
  cp "$HELP_BIN" "$ROOT/bin/help"
fi

chmod +x "$ROOT/bin/busybox"
if [[ -f "$ROOT/bin/bash" ]]; then
  chmod +x "$ROOT/bin/bash"
fi

is_blocked_applet() {
  case "$1" in
    *)
      return 1
      ;;
  esac
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

if [[ -x "$ROOT/bin/help" ]]; then
cat > "$ROOT/.bashrc" <<'BASHRC'
alias help='/bin/help'
BASHRC
fi

cat > "$ROOT/init" <<'INIT'
#!/bin/busybox
if [ -x /bin/bash ]; then
  exec /bin/bash -i
fi
exec /bin/busybox sh -i
INIT
chmod +x "$ROOT/init"

pushd "$ROOT" >/dev/null
find . -print0 | cpio --null -o --format=newc > "$OUT_CPIO"
popd >/dev/null
