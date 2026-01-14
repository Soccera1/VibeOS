# VibeOS

VibeOS is a 32-bit x86 operating system, developed 100% through natural language interaction with AI. It features a monolithic kernel and a POSIX-inspired userland powered by BusyBox.

## Features

- **Bootloader**: Multiboot compliant, booted via GRUB into a graphical framebuffer.
- **CPU Initialization**: GDT (Global Descriptor Table) and IDT (Interrupt Descriptor Table) setup.
- **Memory Management**:
  - Physical Memory Management (PMM).
  - Virtual Memory Management (VMM) with Paging.
- **User Mode**: Support for Ring 3 processes with proper stack initialization (`argc`/`argv`).
- **Filesystem**: Virtual File System (VFS) with a Tar-based Initial RAM Disk (initrd) and improved path resolution.
- **Executable Loading**: ELF32 loader for user-space programs.
- **C Library**: A custom `libc` providing a POSIX-subset necessary for standard Unix utilities.
- **Primary Userland**: Integrated **BusyBox 1.36.1** providing standard tools like `sh` and `ls`.
- **Input/Output**:
  - PS/2 Keyboard driver.
  - Framebuffer-based graphical terminal support.
  - Serial/Debugcon logging (port 0xE9).

## Project Structure

- `src/`: Kernel source code.
  - `arch/i386/`: Architecture-specific assembly and C code.
- `include/`: Header files for kernel and standard C library.
- `user/`: User-space `libc` source, process entry (`start.s`), and custom applications.
- `busybox-1.36.1/`: Vendored BusyBox source code.
- `bin/`: Compiled userland binaries.
- `iso/`: Staging area for the bootable ISO.
- `linker.ld` / `user.ld`: Linker scripts for kernel and userland.

## Prerequisites

To build VibeOS, you will need:

- `gcc` (with i386 support)
- `nasm`
- `make`
- `grub-pc-bin` and `xorriso` (for `grub-mkrescue`)
- `qemu-system-i386` (to run the OS)

## Building

To build the kernel and the bootable ISO:

```bash
make
```

To rebuild the BusyBox userland:

```bash
cd busybox-1.36.1 && make
```

## Running

Run VibeOS in QEMU:

```bash
qemu-system-i386 -cdrom vibeos.iso -serial stdio
```

The serial/debug output is directed to the console.

## Userland

The default shell is BusyBox `ash` (available at `/bin/sh`). It provides standard shell features and utilities included in the BusyBox configuration.

## License



TODO (Deciding between 3-Clause BSD and GPLv3). This project is 100% AI-developed.
