# VibeOS

VibeOS is an amd64 monolithic-kernel OS prototype that boots via Multiboot2 and implements a Linux-compatible syscall ABI, allowing it to run upstream BusyBox userspace.

## Features

- **Kernel:** amd64 64-bit long mode, identity-mapped paging for the first 1 GiB.
- **Boot:** Multiboot2 compliant, supports BIOS+GPT and ISO boot via GRUB.
- **Syscalls:** Extensive Linux-style syscall ABI via amd64 `syscall` instruction (60+ syscalls implemented).
- **Process Management:** Support for `fork` (state snapshotting), `execve` (ELF64 loader), and `wait4`.
- **VFS:** Read-only initramfs (`cpio newc`) root with a read-only `ext2` `/usr` mount, plus support for pipes, symlinks, and device nodes (`/dev/tty`, `/dev/null`).
- **I/O:** TTY support over VGA text mode and serial (`COM1`).
- **Hardware:** XSAVE/AVX/SSE enablement, FSGSBASE support.
- **Shells:**
  - **Bash:** Default interactive shell.
  - **BusyBox:** Userspace base system and fallback shell.
  - **file(1):** Static upstream `file` command with a bundled `magic.mgc` database.
  - **Kernel Shell:** Built-in fallback shell (`vibeos#`) with `ls`, `cat`, `clear`, and `help`.

## Build

### Prerequisites

- `gcc`, `ld`, `nasm` (for the kernel)
- `grub-mkrescue`, `grub-install` (for bootable images)
- `xorriso`, `mtools`, `libisoboot` (usually dependencies of `grub-mkrescue`)
- `zig` (required for musl userspace builds via `zig cc`)

### Build Targets

```bash
make iso   # Build bootable ISO image
make disk  # Build BIOS+GPT raw disk image (requires sudo for loop mounts)
```

Artifacts:
- `build/vibeos-kernel.bin`
- `build/initramfs.cpio`
- `build/usr.ext2`
- `build/vibeos.iso`
- `build/vibeos-gpt.img`

## Run

The default `make run` target builds and launches the GPT disk image in QEMU:

```bash
make run
```

Or manually:

```bash
qemu-system-x86_64 \
  -machine q35,accel=kvm:tcg \
  -m 512M \
  -drive format=raw,file=build/vibeos-gpt.img \
  -serial stdio
```

## Userspace Implementation

VibeOS builds BusyBox, Bash, and upstream `file(1)` as static, non-PIE musl binaries so they can run without a dynamic loader. Bash is the default interactive shell, BusyBox provides the base userspace and a fallback shell if Bash is unavailable, and `file` ships with its compiled `magic.mgc` database under `/usr/share/misc`.

The initramfs now carries the root filesystem and an empty `/usr` mountpoint, while a separate `build/usr.ext2` image is loaded as a second Multiboot module and mounted read-only at `/usr`. The initramfs generator automatically populates `/bin` with applet symlinks to the BusyBox binary.
