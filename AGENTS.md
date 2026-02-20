# Repository Guidelines

This document provides guidelines for agents working on the VibeOS codebase. VibeOS is a small amd64 monolithic-kernel OS prototype that boots on BIOS systems and can launch upstream BusyBox userspace on a TTY.

## Project Structure & Module Organization

```
kernel/boot/          # Early boot and interrupt entry in NASM (boot.asm, interrupts.asm)
kernel/src/           # Kernel subsystems in C (console, syscall, userland loader, initramfs, GDT/IDT, input)
kernel/include/      # Shared headers for kernel modules
kernel/linker.ld     # Linker script for kernel binary
tools/               # Build helpers (make_iso.sh, make_initramfs.sh, build_busybox.sh, GPT image tooling)
rootfs/              # Initramfs overlay files (except rootfs/bin/busybox when built binary supplied)
external/busybox-src/# Upstream BusyBox source tree for static userspace builds
external/busybox-static/  # Prebuilt static BusyBox binaries
build/               # Generated artifacts (vibeos-kernel.bin, initramfs.cpio, vibeos.iso, vibeos-gpt.img)
```

### Module Responsibilities

- **kernel/boot/**: Assembly entry points, boot sector, interrupt handlers
- **kernel/src/console.c**: VGA text mode and serial I/O, ANSI escape handling
- **kernel/src/syscall.c**: Linux-style syscall ABI via amd64 `syscall` instruction
- **kernel/src/userland.c**: Userspace entry, ELF loading, context switching
- **kernel/src/initramfs.c**: Read-only VFS for cpio newc format archives
- **kernel/src/gdt.c / idt.c**: Global Descriptor Table and Interrupt Descriptor Table setup
- **kernel/src/input.c**: Keyboard input handling and TTY buffer
- **kernel/src/multiboot2.c**: Multiboot2 bootloader protocol support

## Build Commands

### Primary Build Targets

```bash
make iso         # Build kernel + initramfs + bootable BIOS ISO (most common)
make disk        # Build BIOS+GPT raw disk image (requires root/loop devices)
make run         # Launch QEMU from GPT disk image
make clean       # Remove all build artifacts
```

### Individual Component Builds

```bash
# Build kernel only (outputs build/vibeos-kernel.bin)
make build/vibeos-kernel.bin

# Build initramfs only (outputs build/initramfs.cpio)
make build/initramfs.cpio

# Build BusyBox userspace
make build/userspace/busybox
```

### Toolchain Requirements

The build system requires:
- **gcc**: `gcc`
- **GNU ld**: `ld`
- **nasm**: Assembly compiler
- **zig**: Used as `zig cc` for BusyBox source builds
- **grub-mkrescue**: For ISO generation
- **grub-install**: For disk image generation
- **qemu-system-x86_64**: For testing

Verify toolchain with:
```bash
make check-toolchain
```

### Manual QEMU Testing

ISO smoke boot (no disk image required):
```bash
qemu-system-x86_64 -m 512M -cdrom build/vibeos.iso -boot d -serial stdio -display none
```

GPT disk boot:
```bash
qemu-system-x86_64 -machine q35,accel=kvm:tcg -m 512M -drive format=raw,file=build/vibeos-gpt.img -serial stdio
```

### Testing Guidelines

**No formal unit-test framework exists.** All testing is boot-based validation:

1. `make iso` must complete without errors
2. QEMU boot must reach the BusyBox shell prompt
3. Basic TTY functionality must work: `echo`, `ls`, `uname`, `cat`

When changing syscalls, loader, or input code, include a short boot log snippet demonstrating the fix works.

## Code Style Guidelines

### Language Standards

- **C**: Freestanding C with `-std=gnu11` (no standard library)
- **Assembly**: NASM with ELF64 output format
- **Compiler flags**: `-Wall -Wextra -Werror -O2 -fno-stack-protector -fno-pic -fno-omit-frame-pointer -mno-red-zone`

### Indentation & Formatting

- **4-space indentation**: Use spaces, not tabs, in C files
- **Line length**: No hard limit, but prefer lines under 100 characters
- **Braces**: K&R style (opening brace on same line)
- **No trailing whitespace**
- **No unnecessary blank lines**

### Naming Conventions

- **Functions/variables**: `snake_case` (e.g., `console_putc`, `kernel_main`)
- **Macros/constants**: `UPPER_SNAKE_CASE` (e.g., `ARRAY_LEN`, `VGA_WIDTH`)
- **Static functions**: May use shorter names, still snake_case
- **Types**: `snake_case` with `_t` suffix for typedefs (e.g., `struct initramfs_entry`)

### Header Files

- Use `#pragma once` for header guards (not `#ifndef`/`#define`)
- Include order (within kernel):
  1. Associated header (if implementing)
  2. Standard library headers (`<stdint.h>`, `<stdbool.h>`, `<stddef.h>`)
  3. Project headers (`"common.h"`, `"console.h"`, etc.)
- Project headers use double quotes, standard libs use angle brackets
- Prefer forward declarations over including headers when possible

### Code Organization

- Declare interfaces in `kernel/include/*.h`
- Implement in matching `kernel/src/*.c`
- Keep modules focused with single responsibility
- Favor small, explicit helper functions over deeply nested logic

### Functions

- Static functions for internal helpers
- Prefix external functions with module name (e.g., `console_init`, `syscall_init`)
- Use `__attribute__((noreturn))` for functions that never return
- Prefer early returns to reduce nesting

### Types and Type Safety

- Use fixed-width integers: `uint8_t`, `uint16_t`, `uint32_t`, `uint64_t`, `int64_t`
- Use `size_t` for sizes and counts
- Use `bool` for booleans (include `<stdbool.h>`)
- Explicit casts when converting between types
- Use `unsigned` for bitwise operations

### Error Handling

- Return `int` for functions that may fail: 0 for success, -1 for error
- Check all return values from I/O operations
- Use `NULL` pointer checks before dereferencing
- For optional data, check existence before use

### Inline Assembly

- Use `__asm__ volatile` for inline assembly
- Specify all input/output/clobber constraints explicitly
- Use local variables for cpuid values (see `kernel/src/main.c`)

### Preprocessor

- Use `ARRAY_LEN(x)` macro for array sizes (defined in `common.h`)
- Use `likely(x)` and `unlikely(x)` branch hints for performance-critical paths
- Avoid macros when inline functions can work

### Console/Output Functions

- Use `console_putc()` for single characters
- Use `console_write()` for null-terminated strings
- Use `console_writen()` for fixed-length strings
- Use `console_printf()` for formatted output (supports %c, %s, %d, %u, %x, %p, %%)

### Documentation

- **No comments unless necessary**: Let code be self-documenting
- **Complex algorithms**: Add brief comment explaining approach, not implementation
- **Non-obvious behavior**: Document with short comment
- **Public APIs**: Declarations in headers should be self-explanatory

## Commit & Pull Request Guidelines

### Commit Messages

Use imperative mood with subsystem prefix:
```
kernel: fix tty input echo duplication
tools: build BusyBox with zig cc musl target
initramfs: handle empty cpio archives gracefully
```

Keep commits scoped by subsystem (`kernel`, `tools`, `rootfs`, `docs`).

### PR Description Should Include

- Problem statement and approach
- Commands run for validation
- Notable runtime output (serial log/QEMU output)
- Any host prerequisites (e.g., `grub-install`, loop devices, root permissions)

## Common Development Tasks

### Adding a New Syscall

1. Add syscall number to appropriate location
2. Implement handler in `kernel/src/syscall.c`
3. Register in syscall table
4. Test with QEMU boot and verify behavior

### Adding a New Kernel Module

1. Create header in `kernel/include/` with function declarations
2. Create implementation in `kernel/src/`
3. Add source file to `KERNEL_C` in Makefile (if new file)
4. Call init function from `kernel_main()` in `main.c`

### Modifying Boot Process

- Assembly entry: `kernel/boot/boot.asm`
- Interrupt handlers: `kernel/boot/interrupts.asm`
- GDT/IDT setup: `kernel/src/gdt.c`, `kernel/src/idt.c`

### Debugging

- Use `console_printf()` for kernel debugging
- Serial output goes to COM1 (use `-serial stdio` in QEMU)
- VGA output visible in QEMU with display (remove `-display none`)

## Tool Paths and Configuration

The Makefile uses these fixed paths:
- CC: `gcc`
- LD: `ld`
- NASM: `nasm` (system installed)

Kernel linker script: `kernel/linker.ld` (sets entry point and memory layout)
