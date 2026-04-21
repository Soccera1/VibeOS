#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <output.cpio> <busybox-bin> [bash-bin] [sl-bin] [help-bin] [file-bin] [file-magic]" >&2
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

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

ROOT="$WORKDIR/root"
mkdir -p "$ROOT"/{bin,dev,etc,proc,sys,tmp,usr/bin,var,home}

if [[ -d rootfs ]]; then
  pushd rootfs >/dev/null
  find . -mindepth 1 ! -path './bin/busybox' -print0 | cpio --null -pdm "$ROOT" >/dev/null 2>&1 || true
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
  mkdir -p "$ROOT/usr/bin"
  ln -sf /bin/bash "$ROOT/usr/bin/bash"
fi

if [[ -n "$SL_BIN" && -x "$SL_BIN" ]]; then
  mkdir -p "$ROOT/usr/bin"
  cp "$SL_BIN" "$ROOT/usr/bin/sl"
fi

if [[ -n "$HELP_BIN" && -x "$HELP_BIN" ]]; then
  cp "$HELP_BIN" "$ROOT/bin/help"
fi

if [[ -n "$FILE_BIN" && -x "$FILE_BIN" ]]; then
  mkdir -p "$ROOT/usr/bin"
  cp "$FILE_BIN" "$ROOT/usr/bin/file"
fi

if [[ -n "$FILE_MAGIC" && -f "$FILE_MAGIC" ]]; then
  mkdir -p "$ROOT/usr/share/misc"
  cp "$FILE_MAGIC" "$ROOT/usr/share/misc/magic.mgc"
fi

if [[ -f external/ncurses-src/build-musl/share/terminfo/l/linux ]]; then
  mkdir -p "$ROOT/usr/share/terminfo/l"
  cp external/ncurses-src/build-musl/share/terminfo/l/linux "$ROOT/usr/share/terminfo/l/linux"
fi

if [[ -f external/ncurses-src/build-musl/share/terminfo/d/dumb ]]; then
  mkdir -p "$ROOT/usr/share/terminfo/d"
  cp external/ncurses-src/build-musl/share/terminfo/d/dumb "$ROOT/usr/share/terminfo/d/dumb"
fi

chmod +x "$ROOT/bin/busybox"
if [[ -f "$ROOT/bin/bash" ]]; then
  chmod +x "$ROOT/bin/bash"
fi
if [[ -f "$ROOT/usr/bin/file" ]]; then
  chmod +x "$ROOT/usr/bin/file"
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
