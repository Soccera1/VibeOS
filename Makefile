SHELL := /bin/bash

BUILD_DIR := build
KERNEL_BIN := $(BUILD_DIR)/vibeos-kernel.bin
INITRAMFS := $(BUILD_DIR)/initramfs.cpio
USR_EXT2 := $(BUILD_DIR)/usr.ext2
ISO_IMAGE := $(BUILD_DIR)/vibeos.iso
DISK_IMAGE := $(BUILD_DIR)/vibeos-gpt.img

CC := gcc
LD := ld
NASM := nasm
USER_CC := gcc
BUSYBOX_SRC := external/busybox-src
BUSYBOX_STATIC := external/busybox-static
BUSYBOX_ROOTFS := rootfs/bin/busybox
COREUTILS_SRC := external/coreutils-src
ZIG_GLOBAL_CACHE := $(BUSYBOX_SRC)/.zig-global-cache
ZIG_LOCAL_CACHE := $(BUSYBOX_SRC)/.zig-local-cache
COREUTILS_ZIG_GLOBAL_CACHE := $(COREUTILS_SRC)/.zig-global-cache
COREUTILS_ZIG_LOCAL_CACHE := $(COREUTILS_SRC)/.zig-local-cache

CFLAGS := -m64 -ffreestanding -fno-stack-protector -fno-pie -fno-pic -fno-omit-frame-pointer -fno-builtin \
	-mno-red-zone -mno-mmx -mno-sse -mno-sse2 -mcmodel=large -Wall -Wextra -Werror -O2 -std=gnu11 -Ikernel/include
LDFLAGS := -nostdlib -z max-page-size=0x1000 -T kernel/linker.ld

KERNEL_ASM := \
	kernel/boot/boot.asm \
	kernel/boot/interrupts.asm

KERNEL_C := $(shell find kernel/src -name '*.c' | sort)
KERNEL_OBJS := $(patsubst %.asm,$(BUILD_DIR)/%.o,$(KERNEL_ASM)) \
	$(patsubst %.c,$(BUILD_DIR)/%.o,$(KERNEL_C))

USER_BUSYBOX := $(BUILD_DIR)/userspace/busybox
USER_COREUTILS := $(BUILD_DIR)/userspace/coreutils
USER_COREUTILS_PROGS := $(BUILD_DIR)/userspace/coreutils-programs.txt
USER_BASH := $(BUILD_DIR)/userspace/bash
USER_HELP := $(BUILD_DIR)/userspace/help
USER_FILE := $(BUILD_DIR)/userspace/file
USER_FILE_MAGIC := $(BUILD_DIR)/userspace/file-magic.mgc
USER_NANO := $(BUILD_DIR)/userspace/nano
USER_MAN_PAGES := $(BUILD_DIR)/userspace/man-pages
USER_LIBPIPELINE := $(BUILD_DIR)/userspace/libpipeline
USER_GROFF := $(BUILD_DIR)/userspace/groff
USER_MAN_DB := $(BUILD_DIR)/userspace/man-db
BASH_SRC := external/bash-src
NCURSES_SRC := external/ncurses-src
NCURSES_BUILD := $(NCURSES_SRC)/build-musl
SL_SRC := external/sl-src
FILE_SRC := external/file-src
NANO_SRC := external/nano-src
MAN_PAGES_SRC := external/man-pages-src
LIBPIPELINE_SRC := external/libpipeline-src
GROFF_SRC := external/groff-src
MAN_DB_SRC := external/man-db-src
USER_SL := $(BUILD_DIR)/userspace/sl
HELP_SRC := userspace/help.c

.PHONY: all clean run iso disk check-toolchain

all: disk

check-toolchain:
	@command -v $(CC) >/dev/null
	@command -v $(LD) >/dev/null
	@command -v $(NASM) >/dev/null
	@command -v grub-mkrescue >/dev/null
	@command -v grub-install >/dev/null
	@command -v mkfs.ext2 >/dev/null
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

$(USER_COREUTILS): | $(BUILD_DIR)
	./tools/build_coreutils.sh $@ "$(USER_COREUTILS_PROGS)" "$(COREUTILS_SRC)"

$(USER_COREUTILS_PROGS): $(USER_COREUTILS)
	@test -f "$@"

$(USER_BASH): $(NCURSES_BUILD)/lib/libncursesw.a | $(BUILD_DIR)
	./tools/build_bash.sh $@ "$(BASH_SRC)"

$(NCURSES_BUILD)/lib/libncursesw.a: | $(BUILD_DIR)
	./tools/build_ncurses.sh $@ "$(NCURSES_SRC)"

$(USER_SL): $(NCURSES_BUILD)/lib/libncursesw.a | $(BUILD_DIR)
	./tools/build_sl.sh $@ "$(SL_SRC)" "$(NCURSES_BUILD)"

$(USER_HELP): $(HELP_SRC) | $(BUILD_DIR)
	./tools/build_help.sh $@ "$(HELP_SRC)"

$(USER_FILE): | $(BUILD_DIR)
	./tools/build_file.sh $@ "$(USER_FILE_MAGIC)" "$(FILE_SRC)"

$(USER_FILE_MAGIC): $(USER_FILE)
	@test -f "$@"

$(USER_NANO): $(NCURSES_BUILD)/lib/libncursesw.a | $(BUILD_DIR)
	./tools/build_nano.sh $@ "$(NANO_SRC)"

$(USER_MAN_PAGES): | $(BUILD_DIR)
	./tools/build_man_pages.sh $@ "$(MAN_PAGES_SRC)"

$(USER_LIBPIPELINE): | $(BUILD_DIR)
	./tools/build_libpipeline.sh $@ "$(LIBPIPELINE_SRC)"

$(USER_GROFF): | $(BUILD_DIR)
	./tools/build_groff.sh $@ "$(GROFF_SRC)"

$(USER_MAN_DB): $(USER_LIBPIPELINE) $(USER_GROFF) | $(BUILD_DIR)
	./tools/build_man_db.sh $@ "$(MAN_DB_SRC)" "$(USER_LIBPIPELINE)" "$(USER_GROFF)"

$(INITRAMFS): tools/make_initramfs.sh $(USER_BUSYBOX) $(USER_HELP) $(USER_COREUTILS) $(USER_COREUTILS_PROGS)
	./tools/make_initramfs.sh $@ $(USER_BUSYBOX) $(USER_HELP) $(USER_COREUTILS) $(USER_COREUTILS_PROGS)

$(USR_EXT2): tools/make_usr_ext2.sh $(USER_BASH) $(USER_HELP) $(USER_SL) $(USER_FILE) $(USER_FILE_MAGIC) $(USER_NANO) $(USER_COREUTILS) $(USER_COREUTILS_PROGS) $(USER_MAN_PAGES) $(USER_GROFF) $(USER_MAN_DB)
	./tools/make_usr_ext2.sh $@ $(USER_BASH) $(USER_HELP) $(USER_SL) $(USER_FILE) $(USER_FILE_MAGIC) $(USER_NANO) $(USER_COREUTILS) $(USER_COREUTILS_PROGS) $(USER_MAN_PAGES) $(USER_GROFF) $(USER_MAN_DB)

iso: check-toolchain $(KERNEL_BIN) $(INITRAMFS) $(USR_EXT2)
	./tools/make_iso.sh $(ISO_IMAGE) $(KERNEL_BIN) $(INITRAMFS) $(USR_EXT2)

# BIOS + GPT raw disk image. Needs loop devices and mount permissions.
disk: check-toolchain $(KERNEL_BIN) $(INITRAMFS) $(USR_EXT2)
	./tools/make_gpt_disk.sh $(DISK_IMAGE) $(KERNEL_BIN) $(INITRAMFS) $(USR_EXT2)

run: disk
	qemu-system-x86_64 \
		-machine q35,accel=kvm:tcg \
		-m 1G \
		-drive format=raw,file=$(DISK_IMAGE) \
		-serial stdio

clean:
	rm -rf $(BUILD_DIR) $(ZIG_GLOBAL_CACHE) $(ZIG_LOCAL_CACHE) $(COREUTILS_ZIG_GLOBAL_CACHE) $(COREUTILS_ZIG_LOCAL_CACHE)
