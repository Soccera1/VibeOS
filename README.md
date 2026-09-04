# VibeOS

VibeOS is an amd64 monolithic-kernel OS prototype that boots via Multiboot2 and implements a Linux-compatible syscall ABI. Static musl and dynamically linked glibc executables are both supported as first-class userspace targets.

## Features

- **Kernel:** amd64 64-bit long mode, identity-mapped bootstrap paging for the first 4 GiB.
- **Boot:** Multiboot2 compliant, supports BIOS+GPT and ISO boot via GRUB.
- **Syscalls:** Extensive Linux-style syscall ABI via amd64 `syscall` instruction (70+ syscalls implemented).
- **Scheduling and clocks:** 100 Hz PIT-driven userspace and kernel preemption, round-robin scheduling, saved x87/SSE/AVX state, and PIT-calibrated TSC timekeeping with separate monotonic and RTC-seeded realtime clocks. Per-process kernel stacks preserve interrupted syscalls; a preemptible global lock serializes legacy kernel operations.
- **Process Management:** Support for `fork` (state snapshotting), `execve` (ELF64 loader), and `wait4`.
- **VFS:** Read-only initramfs (`cpio newc`) root with an `ext2`/`ext3` or read-only XFS `/usr` mount path, a writable `/home` ext3 mount or ramdisk fallback, a writable volatile `/tmp` ramdisk, plus support for pipes, symlinks, Unix-domain sockets, and device nodes (`/dev/tty`, `/dev/null`, `/dev/fb0`). The shipped `/usr` image is XFS; `/home` remains ext3.
- **I/O:** TTY support over VGA text mode, Multiboot/virtio framebuffer, keyboard, and serial (`COM1`).
- **Graphics:** XLibre's Xfbdev and Xvfb servers, evdev keyboard/pointer input, xinit, XKB data, st 0.9.3 as the default X terminal, an xterm fallback, and a small Xlib probe client.
- **Networking:** virtio-net with a small IPv4 stack covering ARP, DHCP, ICMP, UDP, and client-side TCP streams.
- **Hardware:** XSAVE/AVX/SSE enablement, FSGSBASE support.
- **Shells:**
  - **Bash:** Default interactive shell.
  - **GNU coreutils:** Primary implementation for standard file/text/process utilities.
  - **BusyBox:** Fallback shell and provider for non-coreutils applets.
  - **file(1):** Static upstream `file` command with a bundled `magic.mgc` database.
  - **man + groff:** Upstream manual page reader and formatter under `/usr`.
  - **VibeOS man-pages:** A VibeOS-curated edition of Linux man-pages staged under `/usr/share/man`.
  - **less:** Static upstream pager used by `man` and interactive workflows.

## Build

### Prerequisites

- `gcc`, `ld`, `nasm` (for the kernel)
- `grub-mkrescue`, `grub-mkimage` (for bootable images)
- `mkfs.xfs` (xfsprogs), `mkfs.ext3`, and `parted` (for XFS, ext3, and GPT images)
- `qemu-system-x86_64` (for `make run`)
- `xorriso`, `mtools`, `libisoboot` (usually dependencies of `grub-mkrescue`)
- `zig` (required for musl userspace builds via `zig cc`)
- `meson`, `ninja`, `pkg-config`, `gperf`, `tic`, and Autotools when `USER_X11` is enabled; its dependency source trees are bundled under `external/`

### Build Targets

```bash
make iso   # Build bootable ISO image
make disk  # Build BIOS+GPT raw disk image without root privileges
```

Each image target checks only the host tools it actually needs before starting.
Run `make check-toolchain` to preflight the combined ISO, disk, and QEMU toolset.
Run `make check` for static-musl host-side regression tests that do not require
booting VibeOS. Run `make check-preemption-system` for QEMU tests of CPU-bound
processes, long kernel syscalls, queued syscall contention, timer signals,
sleeping-process wakeups, and floating-point state preservation with static musl and dynamic glibc, including a non-XSAVE CPU.

### Configuration

VibeOS has a small Kconfig-like configuration layer. A missing `.config` is
created from defaults automatically during a normal build.

```bash
make defconfig       # Reset .config to defaults
make olddefconfig    # Refresh .config after Kconfig changes
make menuconfig      # Toggle options in a C ncurses menu
make savedefconfig   # Write a minimal defconfig
```

The generated files live under `build/`:

- `build/config.mk` for Makefile conditionals
- `build/include/generated/autoconf.h` for kernel C code

The default configuration preserves the existing full image. Current options
cover binary stripping, kernel build and device settings, and which optional userspace packages
are staged into the initramfs and `/usr` image. BusyBox remains mandatory
because it provides the initramfs base shell and login applets. `make
menuconfig` builds the host helper `build/tools/menuconfig` from
`tools/menuconfig.c` and links it against ncurses.

The Kernel menu includes:

- `KERNEL_WERROR`: treat compiler warnings as errors (enabled by default).
- `KERNEL_DEBUG_INFO`: generate C and assembly debug symbols and retain them in
  the kernel even when `STRIP_BINARIES` is enabled (disabled by default).
- `KERNEL_TIMER_HZ`: scheduler interrupt frequency, default 100 Hz. Values outside
  19–1000 Hz are rejected during compilation; timekeeping uses the calibrated TSC.
- `KERNEL_ATA`, `KERNEL_VIRTIO_SCSI`, `KERNEL_VIRTIO_NET`, and `KERNEL_VIRTIO_GPU`:
  initialize the corresponding hardware (all enabled by default). These switches
  skip device probing; driver code remains linked. Disabling storage drivers can
  make disk-backed filesystems unavailable, disabling VirtIO networking removes
  the network device, and disabling VirtIO graphics leaves the boot framebuffer.

The following feature switches are enabled by default. Names in this table
have the `CONFIG_KERNEL_` prefix in `.config`.

| Menu | Options | Effect when disabled |
| --- | --- | --- |
| Networking | `INET` | Reject IPv4 sockets with `EAFNOSUPPORT`; also disables VirtIO network initialization and dependent IPv4 options. |
| Networking | `UNIX_SOCKETS` | Reject Unix-domain sockets and `socketpair` with `EAFNOSUPPORT`. |
| Networking | `TCP_SOCKETS`, `UDP_SOCKETS`, `RAW_ICMP_SOCKETS` | Reject the corresponding IPv4 socket types with `EPROTOTYPE`. The internal UDP path remains available for DHCP. |
| Networking | `ICMP_ECHO` | Stop replying to incoming ping requests; raw ICMP reception is controlled separately. |
| Filesystems | `EXT2` | Reject ext2/ext3 mounts; also disables ext2 writes and `/home` automount. `/usr` automount remains available when XFS is enabled. |
| Filesystems | `XFS` | Reject XFS mounts. XFS support is read-only and independent of ext2/ext3. |
| Filesystems | `EXT2_WRITE` | Reject writable ext2/ext3 mounts with `EROFS`, while allowing read-only mounts. `/home` can fall back to a ramdisk. |
| Filesystems | `USR_AUTOMOUNT`, `HOME_AUTOMOUNT` | Skip the corresponding disk/image mount at boot. `/home` can still use its ramdisk fallback. |
| Filesystems | `TMP_RAMDISK`, `HOME_RAMDISK` | Disable the writable `/tmp` ramdisk or `/home` ramdisk fallback. |
| Console and input | `SERIAL_CONSOLE`, `SERIAL_INPUT` | Disable serial output or input independently. |
| Console and input | `PS2_KEYBOARD`, `PS2_MOUSE` | Disable the corresponding PS/2 input source. |
| Console and input | `INPUT_EVENTS` | Hide `/dev/input` event devices and stop queuing evdev reports; PS/2 keyboard console input still works. Requires at least one PS/2 input source. |
| Console and input | `FBDEV` | Hide `/dev/fb0` and disable userspace framebuffer access; kernel console rendering remains available. |
| Console and input | `PTYS` | Hide `/dev/ptmx` and `/dev/pts`, disabling pseudo-terminal allocation. |
| Optional system calls | `PIPES` | Return `ENOSYS` from `pipe` and `pipe2`. |
| Optional system calls | `SYMLINK_CREATE`, `HARDLINK_CREATE` | Return `ENOSYS` from link-creation system calls; existing links still work. |
| Optional system calls | `REBOOT`, `SETHOSTNAME` | Return `ENOSYS` from userspace reboot/poweroff or hostname-change requests. Kernel shutdown still works. |

Feature switches control access and initialization, and do not guarantee complete
removal of related code or static buffers from the kernel. Userspace package
selection remains independent: for example, X11 terminal sessions need Unix
sockets, PTYs, framebuffer access and writable temporary storage; shell pipelines
need pipes; network tools need the appropriate socket types. Static musl and
dynamic glibc executable loading remain supported in every configuration.

Run `make check-kernel-config` for static-musl host regression tests covering
default, disabled and mixed feature configurations, dependency resolution,
disabled-interface errors, input handling and ramdisk availability. This check
uses temporary configurations and leaves your `.config` choices intact.

Artifacts:
- `build/vibeos-kernel.bin`
- `build/initramfs.cpio`
- `build/usr.xfs`
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
  -vga none \
  -device virtio-vga \
  -drive format=raw,file=build/vibeos-gpt.img,if=ide,index=0 \
  -device virtio-scsi-pci-transitional,id=scsi0 \
  -drive format=raw,file=build/usr.xfs,if=none,id=usr \
  -device scsi-hd,drive=usr,bus=scsi0.0,scsi-id=0,lun=0 \
  -drive format=raw,file=build/home.ext3,if=none,id=home \
  -device scsi-hd,drive=home,bus=scsi0.0,scsi-id=1,lun=0 \
  -netdev user,id=net0 \
  -device virtio-net-pci-transitional,netdev=net0 \
  -chardev stdio,id=serial0,signal=off \
  -serial chardev:serial0
```

From the VibeOS shell, start the framebuffer X server with:

```bash
startx-vibeos
```

The initial X environment opens st running the default shell and deliberately uses the software framebuffer path. Use `startx-vibeos-xterm` to launch the retained xterm fallback instead. st uses Xft and a minimal Fontconfig configuration over the bundled `misc-fixed` bitmap fonts; its `st-256color` terminfo entry is installed with the runtime. DRM, Mesa, GLX, DRI, udev, and logind are not required or enabled.

## Userspace Implementation

VibeOS ships BusyBox, GNU coreutils, Bash, Vim, upstream `file(1)`, `wget`, and supporting standalone tools as static, non-PIE musl binaries. Dynamic programs use the separately built baseline x86-64 glibc runtime: `/lib64/ld-linux-x86-64.so.2` is in the root image and the core DSOs are under `/usr/lib64`. The shared kernel ELF loader provides strict bounds and architecture validation, safe overlapping-segment mapping, correctly aligned process-entry stacks, stable file identities for DSO deduplication, and meaningful `ENOEXEC` failures. Both static musl and dynamic glibc executables are first-class targets within VibeOS's supported syscall ABI. The integration suite executes a glibc PIE and covers constructors, allocation, auxiliary vectors, direct shared-library linkage, `dlopen`, and `dlsym`. GNU coreutils provides the standard utility set wherever it has an implementation, with the essential commands copied into `/bin` and the rest copied into `/usr/bin` from the separate `/usr` image. BusyBox remains installed for the fallback shell and non-coreutils applets such as `mount`, `ps`, and similar small-system tools. Standalone programs such as Bash, Vim, `file`, `less`, `nano`, `sl`, `man`, `wget`, st, xterm, and the curated `help` command live under `/usr/bin`; Vim also stages a trimmed runtime under `/usr/share/vim`. `file` ships with its compiled `magic.mgc` database under `/usr/share/misc`, groff provides the formatter stack used by `man`, and a VibeOS-curated edition of Linux man-pages is staged under `/usr/share/man`. Unsupported Linux syscall pages are omitted and the retained pages point to VibeOS-specific compatibility notes. The `man` reader is shipped now; `man-db` is built against static musl `libpipeline` and `gdbm`, while the database-maintenance utilities remain omitted from the staged image. `wget` is linked statically against GnuTLS, Nettle, and GMP, and the image stages a CA bundle and `wgetrc` under `/usr/etc`.

Static linking is preferred because self-contained executables fit the VibeOS deployment model, not because musl is preferred. The ideal static target would use glibc, but glibc cannot be made reliably self-contained for facilities that retain dynamic runtime dependencies, including NSS and related loading behavior. Musl is used for static artifacts as a pragmatic compromise. Where dynamic linking is intended, glibc is the preferred and supported libc.

The initramfs now carries the root filesystem, the essential `/bin` command set, BusyBox, and empty `/usr`, `/home`, and `/tmp` mountpoints. The kernel filesystem backends support ext2/ext3 and read-only XFS v4/v5 images. On the default GPT/QEMU run path, `build/usr.xfs` is attached as virtio SCSI target 0 and mounted read-only at `/usr`, while `build/home.ext3` is attached as target 1 and mounted read-write at `/home`; `/tmp` is always backed by a volatile writable ramdisk. Both GPT and ISO GRUB configurations also load `/usr` as a Multiboot module; the kernel prefers that module when present. The kernel can also mount ext2 or ext3 filesystems from regular files through the existing ext2/ext3 loopback path when those files are already reachable through VFS, but there is not yet a kernel block-device/boot-filesystem reader for opening `/boot/usr.xfs` directly from the boot medium.

XFS is enabled by `CONFIG_KERNEL_XFS`. The generic `fs_mount_image`,
`fs_mount_file`, and `fs_mount_storage` kernel APIs detect the filesystem by
magic; explicit `fs_mount_xfs_*` APIs are also available. The default builder produces `build/usr.xfs` for the read-only `/usr` SCSI
disk or Multiboot module. `/home` and the GPT boot partition remain ext3. XFS mounts require `read_only=true`;
requesting a writable XFS `/home` returns `EROFS` and boot uses the home ramdisk
fallback.

The XFS reader supports shortform and block/leaf/node directories, extent and
B+tree data forks, sparse/unwritten extents, inline and remote symlinks, 64-bit
inode numbers, and v5 metadata CRC32c verification. It does **not replay the
journal**: use images created by `mkfs.xfs` or cleanly unmounted on Linux.
Recovery-required images must be recovered on Linux before use. Realtime data,
external logs, metadata-directory formats, special-file inodes, and unknown
incompatible features are unsupported. Mount points must be immediately below
root, with at most four XFS mounts; existing namespace path/name limits apply.

Run `make check-xfs` for static musl host tests, including real images generated
by `mkfs.xfs` (requires host `xfsprogs`). The tests never mount an image or need
root privileges. They also exercise disabled support, invalid metadata, sparse
and unwritten extents, B+tree traversal, and read-only enforcement.

`tools/make_usr_xfs.sh` stages the `/usr` tree and uses
`tools/make_xfs_image.py` to populate XFS through a `mkfs.xfs` prototype, without
root access or loop mounts. The image is at least 384 MiB and grows with the
payload; the GPT disk is sized to hold it. Prototype names and symlink targets
must contain no whitespace and must not start with `:` or `$`; unsupported
entries fail the build explicitly. Regular files, directories, symlinks, and
permission/ownership bits are preserved (sticky modes are unsupported).

The kernel places its heap after the boot modules so the larger XFS image
cannot overlap allocations. With the current fixed memory layout, Multiboot
modules and boot information must finish below 512 MiB to leave room for the
256 MiB heap before the initramfs copy.
