#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <output.iso> <kernel.bin> <initramfs.cpio>" >&2
  exit 1
fi

OUT_ISO="$1"
KERNEL_BIN="$2"
INITRAMFS="$3"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

ISO_ROOT="$WORKDIR/isodir"
mkdir -p "$ISO_ROOT/boot/grub"

cp "$KERNEL_BIN" "$ISO_ROOT/boot/vibeos-kernel.bin"
cp "$INITRAMFS" "$ISO_ROOT/boot/initramfs.cpio"

cat > "$ISO_ROOT/boot/grub/grub.cfg" <<'CFG'
set timeout=0
set default=0

menuentry "VibeOS" {
    multiboot2 /boot/vibeos-kernel.bin
    module2 /boot/initramfs.cpio
    boot
}
CFG

mkdir -p "$(dirname "$OUT_ISO")"
grub-mkrescue -o "$OUT_ISO" "$ISO_ROOT" >/dev/null
