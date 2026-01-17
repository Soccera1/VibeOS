CC = gcc
AS = nasm
LD = ld

CFLAGS = -m32 -ffreestanding -O2 -Wall -Wextra -Iinclude -fno-pie -mno-sse -mno-mmx -mno-sse2 -fno-stack-protector
ASFLAGS = -f elf32
LDFLAGS = -m32 -nostdlib -T linker.ld

OBJS = src/arch/i386/boot.o \
       src/kernel.o \
       src/gdt.o \
       src/arch/i386/gdt_flush.o \
       src/idt.o \
       src/arch/i386/idt_load.o \
       src/common.o \
       src/pic.o \
       src/isr.o \
       src/arch/i386/interrupt.o \
       src/arch/i386/user_mode.o \
       src/keyboard.o \
       src/pmm.o \
       src/vmm.o \
       src/vfs.o \
       src/tar.o \
       src/elf.o \
       src/syscall.o \
       src/arch/i386/syscall_stub.o \
       src/font.o \
       src/terminal.o

all: vibeos.bin vibeos.iso

vibeos.bin: $(OBJS)
	$(CC) $(LDFLAGS) -o vibeos.bin $(OBJS)

USER_CFLAGS = -m32 -ffreestanding -O0 -Wall -Wextra -Iinclude -fno-pie -fno-stack-protector

user/start.o: user/start.s
	$(AS) -f elf32 user/start.s -o user/start.o

libc.o: user/libc.c
	$(CC) $(USER_CFLAGS) -Iuser -Iinclude -c user/libc.c -o libc.o

sh: user/sh.c libc.o user/start.o
	$(CC) $(USER_CFLAGS) -Iuser -Iinclude -c user/sh.c -o sh.o
	$(LD) -m elf_i386 -T user.ld user/start.o sh.o libc.o -o sh

user_test: user_test.s
	$(AS) -f elf32 user_test.s -o user_test.o
	$(LD) -m elf_i386 -T user.ld user_test.o -o user_test

vibeos.iso: vibeos.bin sh user_test
	mkdir -p iso/boot/grub
	cp vibeos.bin iso/boot/vibeos.bin
	cp grub.cfg iso/boot/grub/grub.cfg
	if [ ! -e bin ]; then \
	mkdir bin; \
	fi
	if [ ! -e bin/sh ]; then \
	cp sh bin/sh; \
	fi
	tar -cvf initrd.tar -C bin sh
	cp initrd.tar iso/boot/initrd.tar
	grub-mkrescue -o vibeos.iso iso

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.s
	$(AS) $(ASFLAGS) $< -o $@

clean:
	rm -f $(OBJS) vibeos.bin vibeos.iso initrd.tar user_test user_test.o sh sh.o libc.o
