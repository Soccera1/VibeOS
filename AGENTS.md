# Repository Guidelines

## Project Structure & Module Organization
- `kernel/boot/`: early boot and interrupt entry in NASM (`boot.asm`, `interrupts.asm`).
- `kernel/src/`: kernel subsystems in C (console, syscall, userland loader, initramfs, GDT/IDT, input).
- `kernel/include/`: shared headers for kernel modules.
- `tools/`: build helpers (`make_iso.sh`, `make_initramfs.sh`, `build_busybox.sh`, GPT image tooling).
- `rootfs/`: initramfs overlay files copied into the runtime filesystem (except `rootfs/bin/busybox` when a built binary is supplied).
- `external/busybox-src/`: upstream BusyBox source tree used for static userspace builds.
- `build/`: generated artifacts (`vibeos-kernel.bin`, `initramfs.cpio`, `vibeos.iso`).

## Build, Test, and Development Commands
- `make iso`: build kernel + initramfs + bootable BIOS ISO.
- `make disk`: build BIOS+GPT raw disk image (`build/vibeos-gpt.img`), typically requires root-capable host tools.
- `make run`: launch QEMU from the GPT disk image.
- `make clean`: remove build artifacts.
- ISO smoke boot:
  `qemu-system-x86_64 -m 512M -cdrom build/vibeos.iso -boot d -serial stdio -display none`

## Coding Style & Naming Conventions
- Languages: freestanding C (`-std=gnu11`) and NASM.
- Use 4-space indentation; no tabs in C files.
- Prefer `snake_case` for functions/variables; `UPPER_SNAKE_CASE` for macros/constants.
- Keep modules focused: declare interfaces in `kernel/include/*.h`, implement in matching `kernel/src/*.c`.
- Favor small, explicit helpers over deeply nested logic in syscall and loader paths.

## Testing Guidelines
- No formal unit-test framework is present yet; use boot-based validation.
- Minimum check before PR:
  1. `make iso` completes.
  2. QEMU boot reaches BusyBox shell prompt.
  3. Basic TTY path works (`echo`, `ls`, `uname`).
- When changing syscalls/loader/input, include a short boot log snippet in the PR.

## Commit & Pull Request Guidelines
- Repository currently has no historical commit convention; use imperative messages:
  - `kernel: fix tty input echo duplication`
  - `tools: build BusyBox with zig cc musl target`
- Keep commits scoped by subsystem (`kernel`, `tools`, `docs`, `rootfs`).
- PRs should include:
  - problem statement and approach,
  - commands run for validation,
  - notable runtime output (serial log/QEMU output),
  - any host prerequisites (e.g., `grub-install`, loop devices, root permissions).
