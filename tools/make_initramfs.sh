#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <output.cpio> <busybox-fallback-bin>" >&2
  exit 1
fi

OUT_CPIO_INPUT="$1"
OUT_CPIO_DIR="$(cd "$(dirname "$OUT_CPIO_INPUT")" && pwd)"
OUT_CPIO="$OUT_CPIO_DIR/$(basename "$OUT_CPIO_INPUT")"
FALLBACK_BUSYBOX="$2"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

ROOT="$WORKDIR/root"
mkdir -p "$ROOT"/{bin,dev,etc,proc,sys,tmp,usr/bin,var,home}

if [[ -d rootfs ]]; then
  pushd rootfs >/dev/null
  find . -mindepth 1 ! -path './bin/busybox' -print0 | cpio --null -pdm "$ROOT" >/dev/null 2>&1 || true
  popd >/dev/null
fi

if [[ -x "$FALLBACK_BUSYBOX" ]]; then
  cp "$FALLBACK_BUSYBOX" "$ROOT/bin/busybox"
elif [[ -x rootfs/bin/busybox ]]; then
  cp rootfs/bin/busybox "$ROOT/bin/busybox"
elif [[ -x external/busybox-static ]]; then
  cp external/busybox-static "$ROOT/bin/busybox"
else
  echo "BusyBox binary missing: $FALLBACK_BUSYBOX" >&2
  exit 1
fi

chmod +x "$ROOT/bin/busybox"

is_blocked_applet() {
  case "$1" in
    # These rely on full-screen terminal modes that VibeOS does not yet support.
    vi|less|more|top)
      return 0
      ;;
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

cat > "$ROOT/init" <<'INIT'
#!/bin/busybox
exec /bin/busybox sh -i
INIT
chmod +x "$ROOT/init"

pushd "$ROOT" >/dev/null
find . -print0 | cpio --null -o --format=newc > "$OUT_CPIO"
popd >/dev/null
