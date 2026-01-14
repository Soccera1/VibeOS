# VibeOS

VibeOS is a hobbyist x86 (32-bit) operating system designed to explore kernel development, memory management, and user-mode transitions.

## Features

- **Bootloader**: Multiboot compliant, booted via GRUB.
- **CPU Initialization**: GDT (Global Descriptor Table) and IDT (Interrupt Descriptor Table) setup.
- **Memory Management**:
  - Physical Memory Management (PMM).
  - Virtual Memory Management (VMM) with Paging.
- **User Mode**: Support for transitioning to Ring 3.
- **Filesystem**: Virtual File System (VFS) with a Tar-based Initial RAM Disk (initrd).
- **Executable Loading**: ELF32 loader for user-space programs.
- **Input/Output**:
  - PS/2 Keyboard driver.
  - Framebuffer-based graphical terminal support.
  - Debugging via serial/debugcon.
- **System Calls**: Infrastructure for user-space to kernel-space communication.
- **Shell**: A basic user-mode shell (`sh`) with command parsing.

## Project Structure

- `src/`: Kernel source code (C and Assembly).
  - `arch/i386/`: Architecture-specific code (boot, interrupts, GDT/IDT flushing).
- `include/`: Header files for kernel and shared structures.
- `user/`: User-space applications and a minimal `libc`.
- `iso/`: Directory structure for creating the bootable ISO.
- `linker.ld`: Kernel linker script.
- `user.ld`: Linker script for user-space programs.
- `Makefile`: Build system configuration.
- `grub.cfg`: GRUB bootloader configuration.

## Prerequisites

To build VibeOS, you will need:

- `gcc` (with i386 support)
- `nasm`
- `ld` (binutils)
- `make`
- `grub-pc-bin` and `xorriso` (for `grub-mkrescue`)
- `qemu-system-i386` (to run the OS)

## Building

To build the kernel and the bootable ISO:

```bash
make
```

This will produce:
- `vibeos.bin`: The kernel executable.
- `vibeos.iso`: The bootable disk image.
- `sh`: The user-mode shell.
- `initrd.tar`: The initial RAM disk containing user programs.

## Running

You can run VibeOS using QEMU:

```bash
qemu-system-i386 -cdrom vibeos.iso
```

To see debug output (if implemented via debugcon):

```bash
qemu-system-i386 -cdrom vibeos.iso -debugcon stdio
```

## Shell Commands

The built-in shell (`sh`) supports the following:

- `help`: Display available commands.
- `ls`: List files in the root directory (from initrd).
- `exec <file>`: Load and execute an ELF binary from the VFS.
- `exit`: Exit the shell.

## License

TODO
