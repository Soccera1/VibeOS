#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 <output.img> <kernel.bin> <initramfs.cpio> <usr.ext3>" >&2
  exit 1
fi

OUT_IMG="$1"
KERNEL_BIN="$2"
INITRAMFS="$3"
USR_EXT3="$4"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

BOOT_ROOT="$WORKDIR/root"
BOOT_IMG="$WORKDIR/boot.img"
CORE_IMG="$WORKDIR/core.img"
PART_IMG="$WORKDIR/vibeos.ext3"
GRUB_DIR="${GRUB_I386_PC_DIR:-/usr/lib/grub/i386-pc}"
mkdir -p "$BOOT_ROOT/boot/grub"

if [[ ! -r "$GRUB_DIR/boot.img" ]]; then
  echo "GRUB i386-pc boot image not found: $GRUB_DIR/boot.img" >&2
  exit 1
fi

cp "$KERNEL_BIN" "$BOOT_ROOT/boot/vibeos-kernel.bin"
cp "$INITRAMFS" "$BOOT_ROOT/boot/initramfs.cpio"
cp "$USR_EXT3" "$BOOT_ROOT/boot/usr.ext3"

cat > "$BOOT_ROOT/boot/grub/grub.cfg" <<'CFG'
set timeout=0
set default=0

insmod all_video
set gfxmode=1024x768x32
set gfxpayload=keep

menuentry "VibeOS" {
    multiboot2 /boot/vibeos-kernel.bin
    module2 /boot/initramfs.cpio
    module2 /boot/usr.ext3
    boot
}
CFG

mkdir -p "$(dirname "$OUT_IMG")"
truncate -s 384M "$OUT_IMG"

parted -s "$OUT_IMG" mklabel gpt
parted -s "$OUT_IMG" mkpart BIOSGRUB 1MiB 3MiB
parted -s "$OUT_IMG" set 1 bios_grub on
parted -s "$OUT_IMG" mkpart VIBEOS ext3 3MiB 100%

mapfile -t PARTITIONS < <(
  parted -ms "$OUT_IMG" unit s print |
    awk -F: '$1 == "1" || $1 == "2" { gsub(/s$/, "", $2); gsub(/s$/, "", $4); print $2, $4 }'
)
if [[ ${#PARTITIONS[@]} -ne 2 ]]; then
  echo "failed to read GPT partition offsets from $OUT_IMG" >&2
  exit 1
fi

read -r BIOS_START BIOS_SECTORS <<< "${PARTITIONS[0]}"
read -r ROOT_START ROOT_SECTORS <<< "${PARTITIONS[1]}"

truncate -s "$((ROOT_SECTORS * 512))" "$PART_IMG"
mkfs.ext3 -q -O ^dir_index -L VIBEOS -d "$BOOT_ROOT" "$PART_IMG"
dd if="$PART_IMG" of="$OUT_IMG" bs=512 seek="$ROOT_START" conv=notrunc status=none

cp "$GRUB_DIR/boot.img" "$BOOT_IMG"
grub-mkimage \
  --format=i386-pc \
  --directory="$GRUB_DIR" \
  --prefix='(hd0,gpt2)/boot/grub' \
  --output="$CORE_IMG" \
  biosdisk part_gpt ext2 multiboot2 normal all_video gfxterm configfile

python3 - "$BOOT_IMG" "$CORE_IMG" "$BIOS_START" "$BIOS_SECTORS" <<'PY'
import os
import struct
import sys

boot_path, core_path, first_sector_arg, available_sectors_arg = sys.argv[1:]
first_sector = int(first_sector_arg)
available_sectors = int(available_sectors_arg)
core_sectors = (os.path.getsize(core_path) + 511) // 512

if os.path.getsize(boot_path) != 512 or core_sectors < 2:
    raise SystemExit("unexpected GRUB i386-pc image layout")
if core_sectors > available_sectors:
    raise SystemExit(
        f"GRUB core image needs {core_sectors} sectors, "
        f"but the BIOS boot partition has only {available_sectors}"
    )

with open(boot_path, "r+b") as boot:
    boot.seek(0x5C)
    boot.write(struct.pack("<Q", first_sector))

with open(core_path, "r+b") as core:
    # diskboot.img occupies the first sector of core.img. Its final blocklist
    # entry tells it where the remaining, contiguous core sectors begin.
    core.seek(512 - 12)
    core.write(struct.pack("<QH", first_sector + 1, core_sectors - 1))
PY

# Preserve the protective GPT partition table at bytes 446-509. GRUB's BIOS
# bootstrap uses bytes 0-439, while the existing 0x55aa signature remains.
dd if="$BOOT_IMG" of="$OUT_IMG" bs=1 count=440 conv=notrunc status=none
dd if="$CORE_IMG" of="$OUT_IMG" bs=512 seek="$BIOS_START" conv=notrunc status=none
