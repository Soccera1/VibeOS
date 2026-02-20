#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <output.img> <kernel.bin> <initramfs.cpio>" >&2
  exit 1
fi

OUT_IMG="$1"
KERNEL_BIN="$2"
INITRAMFS="$3"

if [[ $EUID -eq 0 ]]; then
  SUDO=""
else
  SUDO="sudo"
fi

WORKDIR="$(mktemp -d)"
MNT="$WORKDIR/mnt"
mkdir -p "$MNT"
LOOPDEV=""

cleanup() {
  set +e
  if mountpoint -q "$MNT"; then
    $SUDO umount "$MNT"
  fi
  if [[ -n "$LOOPDEV" ]]; then
    $SUDO losetup -d "$LOOPDEV" >/dev/null 2>&1
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

mkdir -p "$(dirname "$OUT_IMG")"
truncate -s 128M "$OUT_IMG"

parted -s "$OUT_IMG" mklabel gpt
parted -s "$OUT_IMG" mkpart BIOSGRUB 1MiB 3MiB
parted -s "$OUT_IMG" set 1 bios_grub on
parted -s "$OUT_IMG" mkpart VIBEOS ext2 3MiB 100%

LOOPDEV="$($SUDO losetup --find --show --partscan "$OUT_IMG")"

$SUDO mkfs.ext2 -q -L VIBEOS "${LOOPDEV}p2"
$SUDO mount "${LOOPDEV}p2" "$MNT"

$SUDO mkdir -p "$MNT/boot/grub"
$SUDO cp "$KERNEL_BIN" "$MNT/boot/vibeos-kernel.bin"
$SUDO cp "$INITRAMFS" "$MNT/boot/initramfs.cpio"

cat <<'CFG' | $SUDO tee "$MNT/boot/grub/grub.cfg" >/dev/null
set timeout=0
set default=0

menuentry "VibeOS" {
    multiboot2 /boot/vibeos-kernel.bin
    module2 /boot/initramfs.cpio
    boot
}
CFG

$SUDO grub-install \
  --target=i386-pc \
  --boot-directory="$MNT/boot" \
  --modules="part_gpt ext2 multiboot2 normal" \
  --recheck \
  "$LOOPDEV"

$SUDO umount "$MNT"
$SUDO losetup -d "$LOOPDEV"
LOOPDEV=""
