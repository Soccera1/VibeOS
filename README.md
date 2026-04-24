# VibeOS

VibeOS is an amd64 monolithic-kernel OS prototype that boots via Multiboot2 and implements a Linux-compatible syscall ABI, allowing it to run a small static musl userspace built from upstream BusyBox, GNU coreutils, Bash, and other standalone programs.

## Features

- **Kernel:** amd64 64-bit long mode, identity-mapped paging for the first 1 GiB.
- **Boot:** Multiboot2 compliant, supports BIOS+GPT and ISO boot via GRUB.
- **Syscalls:** Extensive Linux-style syscall ABI via amd64 `syscall` instruction (60+ syscalls implemented).
- **Process Management:** Support for `fork` (state snapshotting), `execve` (ELF64 loader), and `wait4`.
- **VFS:** Read-only initramfs (`cpio newc`) root with an `ext2`/`ext3` `/usr` mount path, plus support for pipes, symlinks, and device nodes (`/dev/tty`, `/dev/null`). The shipped `/usr` image is `ext3`.
- **I/O:** TTY support over VGA text mode and serial (`COM1`).
- **Hardware:** XSAVE/AVX/SSE enablement, FSGSBASE support.
- **Shells:**
  - **Bash:** Default interactive shell.
  - **GNU coreutils:** Primary implementation for standard file/text/process utilities.
  - **BusyBox:** Fallback shell and provider for non-coreutils applets.
  - **file(1):** Static upstream `file` command with a bundled `magic.mgc` database.
  - **man + groff:** Upstream manual page reader and formatter under `/usr`.
  - **Linux man-pages:** Upstream manual pages staged under `/usr/share/man`.

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
- `build/usr.ext3`
- `build/home.ext3`
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
  -m 1G \
  -drive format=raw,file=build/vibeos-gpt.img,if=ide,index=0 \
  -device virtio-scsi-pci-transitional,id=scsi0 \
  -drive format=raw,file=build/usr.ext3,if=none,id=usr \
  -device scsi-hd,drive=usr,bus=scsi0.0,scsi-id=0,lun=0 \
  -drive format=raw,file=build/home.ext3,if=none,id=home \
  -device scsi-hd,drive=home,bus=scsi0.0,scsi-id=1,lun=0 \
  -serial stdio
```

## Userspace Implementation

VibeOS currently ships BusyBox, GNU coreutils, Bash, and upstream `file(1)` as static, non-PIE musl binaries. The kernel loader now accepts interpreter-backed ELF64 binaries as well, but that path is still expected to be buggy, and the runtime shared-object loaders and libraries are not staged in the system image yet. Static binaries remain the preferred execution model and are expected to stay that way even if dynamic loading support improves. GNU coreutils provides the standard utility set wherever it has an implementation, with the essential commands copied into `/bin` and the rest copied into `/usr/bin` from the separate `/usr` image. BusyBox remains installed for the fallback shell and the non-coreutils applets such as `vi`, `mount`, `ps`, and similar small-system tools. Standalone programs such as Bash, `file`, `nano`, `sl`, `man`, and the curated `help` command live under `/usr/bin`, `file` ships with its compiled `magic.mgc` database under `/usr/share/misc`, groff provides the formatter stack used by `man`, and the upstream Linux man-pages tree is staged under `/usr/share/man`. The `man` reader is shipped now; `man-db` is built against static musl `libpipeline` and `gdbm`, while the database-maintenance utilities remain omitted from the staged image.

The initramfs now carries the root filesystem, the essential `/bin` command set, BusyBox, and empty `/usr` and `/home` mountpoints. The kernel filesystem backend supports both ext2 and ext3 images. On the default GPT/QEMU run path, `build/usr.ext3` is attached as virtio SCSI target 0 and mounted read-only at `/usr`, while `build/home.ext3` is attached as target 1 and mounted read-write at `/home`. ISO boot still loads `/usr` as a Multiboot module. The kernel can also mount ext2 or ext3 filesystems from regular files through the existing ext2/ext3 loopback path when those files are already reachable through VFS, but there is not yet a kernel block-device/boot-filesystem reader for opening `/boot/usr.ext3` directly from the boot medium.
