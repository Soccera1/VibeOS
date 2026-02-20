SHELL := /bin/bash

BUILD_DIR := build
KERNEL_BIN := $(BUILD_DIR)/vibeos-kernel.bin
INITRAMFS := $(BUILD_DIR)/initramfs.cpio
ISO_IMAGE := $(BUILD_DIR)/vibeos.iso
DISK_IMAGE := $(BUILD_DIR)/vibeos-gpt.img

CC := gcc
LD := ld
NASM := nasm
USER_CC := gcc
BUSYBOX_SRC := external/busybox-src
BUSYBOX_STATIC := external/busybox-static
BUSYBOX_ROOTFS := rootfs/bin/busybox
ZIG_GLOBAL_CACHE := $(BUSYBOX_SRC)/.zig-global-cache
ZIG_LOCAL_CACHE := $(BUSYBOX_SRC)/.zig-local-cache

CFLAGS := -m64 -ffreestanding -fno-stack-protector -fno-pie -fno-pic -fno-omit-frame-pointer -fno-builtin \
	-mno-red-zone -mno-mmx -mno-sse -mno-sse2 -Wall -Wextra -Werror -O2 -std=gnu11 -Ikernel/include
LDFLAGS := -nostdlib -z max-page-size=0x1000 -T kernel/linker.ld

KERNEL_ASM := \
	kernel/boot/boot.asm \
	kernel/boot/interrupts.asm

KERNEL_C := $(shell find kernel/src -name '*.c' | sort)
KERNEL_OBJS := $(patsubst %.asm,$(BUILD_DIR)/%.o,$(KERNEL_ASM)) \
	$(patsubst %.c,$(BUILD_DIR)/%.o,$(KERNEL_C))

USER_BUSYBOX := $(BUILD_DIR)/userspace/busybox

.PHONY: all clean run iso disk check-toolchain

all: disk

check-toolchain:
	@command -v $(CC) >/dev/null
	@command -v $(LD) >/dev/null
	@command -v $(NASM) >/dev/null
	@command -v grub-mkrescue >/dev/null
	@command -v grub-install >/dev/null
	@command -v qemu-system-x86_64 >/dev/null

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/kernel/boot/%.o: kernel/boot/%.asm | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(NASM) -f elf64 $< -o $@

$(BUILD_DIR)/kernel/src/%.o: kernel/src/%.c | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(KERNEL_BIN): $(KERNEL_OBJS) kernel/linker.ld | $(BUILD_DIR)
	$(LD) $(LDFLAGS) -o $@ $(KERNEL_OBJS)

$(USER_BUSYBOX): | $(BUILD_DIR)
	./tools/build_busybox.sh $@ "$(BUSYBOX_SRC)" "$(BUSYBOX_STATIC)" "$(BUSYBOX_ROOTFS)"

$(INITRAMFS): $(USER_BUSYBOX)
	./tools/make_initramfs.sh $@ $(USER_BUSYBOX)

iso: check-toolchain $(KERNEL_BIN) $(INITRAMFS)
	./tools/make_iso.sh $(ISO_IMAGE) $(KERNEL_BIN) $(INITRAMFS)

# BIOS + GPT raw disk image. Needs loop devices and mount permissions.
disk: check-toolchain $(KERNEL_BIN) $(INITRAMFS)
	./tools/make_gpt_disk.sh $(DISK_IMAGE) $(KERNEL_BIN) $(INITRAMFS)

run: disk
	qemu-system-x86_64 \
		-machine q35,accel=kvm:tcg \
		-m 512M \
		-drive format=raw,file=$(DISK_IMAGE) \
		-serial stdio

clean:
	rm -rf $(BUILD_DIR) $(ZIG_GLOBAL_CACHE) $(ZIG_LOCAL_CACHE)
