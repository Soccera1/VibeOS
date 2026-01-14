# VibeOS Project Context

VibeOS is a 32-bit x86 operating system that is 100% AI-developed. It was created entirely through natural language interaction via the Gemini CLI; the human user has never opened an editor or manually modified the source code. The project consists of a monolithic kernel and a minimal userland environment, implementing core OS concepts like multitasking, virtual memory, and a virtual file system.

## Project Overview

- **Kernel**: A 32-bit x86 monolithic kernel.
    - **Architecture**: i386 (x86 32-bit).
    - **Boot**: Multiboot 1 compliant, boots via GRUB into a graphical framebuffer.
    - **Memory Management**: Physical Memory Manager (PMM) and Virtual Memory Manager (VMM) with paging.
    - **VFS**: Virtual File System supporting an initrd (TAR format) loaded as a Multiboot module.
    - **Executables**: Supports loading and executing ELF binaries in user mode.
    - **System Calls**: Interface via `int 0x80`.
- **Userland**:
    - **libc**: A minimal C library for user-mode programs.
    - **sh**: A simple interactive shell supporting built-in commands like `ls`, `help`, and `exec`.

## Key Technologies

- **Languages**: C, x86 Assembly (NASM).
- **Toolchain**: GCC, LD, NASM.
- **Bootloader**: GRUB (`grub-mkrescue`).
- **Target**: i386-elf (freestanding).

## Building and Running

### Build Commands
- `make`: Compiles the kernel, userland programs, prepares the initrd, and generates `vibeos.iso`.
- `make clean`: Cleans up all build artifacts.

### Running in QEMU
To run VibeOS, use QEMU with the generated ISO:
```bash
qemu-system-i386 -cdrom vibeos.iso -serial stdio
```
*Note: The kernel writes debug information to the Bochs/QEMU debug console (port 0xE9).*

## Directory Structure

- `src/`: Kernel source files.
    - `arch/i386/`: Architecture-specific assembly and C code (boot, GDT/IDT loading, interrupts).
- `include/`: Kernel and shared headers.
    - `kernel/`: Kernel-internal headers.
    - `vibeos/`: Headers shared with userland (e.g., syscall definitions).
- `user/`: User-mode programs and minimal libc implementation.
- `iso/`: Staging area for creating the bootable ISO.
- `grub.cfg`: Configuration for the GRUB bootloader.
- `linker.ld`: Linker script for the kernel.
- `user.ld`: Linker script for user-mode programs.

## Development Conventions

- **System Calls**: Defined in `include/vibeos/syscall.h`. Implemented in `src/syscall.c`.
- **Memory Layout**:
    - Kernel starts at 1MB (`0x100000`).
    - User stack is typically mapped near `0x500000`.
- **Debugging**: Use `print_debugcon` for kernel-level logging (outputs to port 0xE9).
- **Style**: Follow existing C patterns. Freestanding environment (no standard `malloc`, `printf` in kernel unless implemented).
