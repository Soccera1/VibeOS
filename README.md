# VibeOS

VibeOS is a small amd64 monolithic-kernel OS prototype that boots on BIOS systems and can launch upstream BusyBox userspace on a TTY.

## What it includes

- 32-bit BIOS bootstrap to 64-bit long mode.
- Identity-mapped paging for the first 1 GiB.
- GDT/TSS + IDT setup.
- Userspace entry (`ring3`) and Linux-style syscall ABI via amd64 `syscall` (plus `int 0x80` compatibility path).
- Initramfs (`cpio newc`) read-only VFS.
- TTY I/O over VGA + serial (`COM1`).
- GPT+BIOS raw disk image tooling with GRUB.

## Build

```bash
make iso
```

Artifacts:

- `build/vibeos-kernel.bin`
- `build/initramfs.cpio`
- `build/vibeos.iso`

## Run (ISO)

```bash
qemu-system-x86_64 \
  -m 512M \
  -cdrom build/vibeos.iso \
  -boot d \
  -serial stdio \
  -display none
```

## Build BIOS+GPT disk image

```bash
make disk
```

`make disk` uses loop devices, filesystem formatting, mounting, and `grub-install`, so it usually requires root/sudo.

## Run (GPT disk)

```bash
qemu-system-x86_64 \
  -m 512M \
  -drive format=raw,file=build/vibeos-gpt.img \
  -serial stdio \
  -display none
```

## Upstream BusyBox payload

`make` now prefers building real upstream BusyBox from source:

1. `external/busybox-src` (build from source)
2. `busybox-*.tar.*` in repository root (auto-extract to `external/busybox-src` and build)
3. `rootfs/bin/busybox` (prebuilt fallback)
4. `external/busybox-static` (prebuilt fallback)

If `zig` is available, `tools/build_busybox.sh` builds BusyBox with `zig cc -target x86_64-linux-musl` (local zig caches under `external/busybox-src`) and enforces static non-PIE ELF64 (`ET_EXEC`).

The initramfs generator creates common applet symlinks in `/bin`.
