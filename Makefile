SHELL := /bin/bash

BUILD_DIR := build
KCONFIG := Kconfig
CONFIG_FILE := .config
KCONFIG_TOOL := tools/kconfig.py
MENUCONFIG := $(BUILD_DIR)/tools/menuconfig
CONFIG_MK := $(BUILD_DIR)/config.mk
CONFIG_HEADER := $(BUILD_DIR)/include/generated/autoconf.h
KERNEL_BIN := $(BUILD_DIR)/vibeos-kernel.bin
INITRAMFS := $(BUILD_DIR)/initramfs.cpio
USR_EXT3 := $(BUILD_DIR)/usr.ext3
HOME_EXT3 := $(BUILD_DIR)/home.ext3
ISO_IMAGE := $(BUILD_DIR)/vibeos.iso
DISK_IMAGE := $(BUILD_DIR)/vibeos-gpt.img
DOCS_DIR := docs
DOCS_SRC := $(DOCS_DIR)/vibeos.texi
DOCS_OUT := $(DOCS_DIR)/out
DOCS_INFO := $(DOCS_OUT)/vibeos.info
DOCS_HTML := $(DOCS_OUT)/vibeos.html
DOCS_HTML_SPLIT := $(DOCS_OUT)/html
DOCS_PDF := $(DOCS_OUT)/vibeos.pdf
DOCS_PDF_BUILD := $(DOCS_OUT)/.texi2pdf

CC := gcc
LD := ld
NASM := nasm
STRIP ?= strip
HOST_CC ?= cc
PKG_CONFIG ?= pkg-config
USER_CC := gcc
BUSYBOX_SRC := external/busybox-src
BUSYBOX_STATIC := external/busybox-static
BUSYBOX_ROOTFS := rootfs/bin/busybox
COREUTILS_SRC := external/coreutils-src
ZIG_GLOBAL_CACHE := $(BUSYBOX_SRC)/.zig-global-cache
ZIG_LOCAL_CACHE := $(BUSYBOX_SRC)/.zig-local-cache
COREUTILS_ZIG_GLOBAL_CACHE := $(COREUTILS_SRC)/.zig-global-cache
COREUTILS_ZIG_LOCAL_CACHE := $(COREUTILS_SRC)/.zig-local-cache
NCURSES_CFLAGS := $(shell $(PKG_CONFIG) --cflags ncursesw 2>/dev/null)
NCURSES_LIBS := $(or $(shell $(PKG_CONFIG) --libs ncursesw 2>/dev/null),-lncursesw)

CFLAGS := -m64 -ffreestanding -fno-stack-protector -fno-pie -fno-pic -fno-omit-frame-pointer -fno-builtin \
	-mno-red-zone -mno-mmx -mno-sse -mno-sse2 -mcmodel=large -Wall -Wextra -O2 -std=gnu11 \
	-Ikernel/include -I$(BUILD_DIR)/include -include generated/autoconf.h
LDFLAGS := -nostdlib -z max-page-size=0x1000 -T kernel/linker.ld

CONFIG_GOALS := config oldconfig menuconfig defconfig olddefconfig savedefconfig clean
ifeq ($(filter $(CONFIG_GOALS),$(MAKECMDGOALS)),)
-include $(CONFIG_MK)
endif

CONFIG_STRIP_BINARIES ?= y
CONFIG_KERNEL_WERROR ?= y
CONFIG_USER_HELP ?= y
CONFIG_USER_COREUTILS ?= y
CONFIG_USER_BASH ?= y
CONFIG_USER_FILE ?= y
CONFIG_USER_NANO ?= y
CONFIG_USER_LESS ?= y
CONFIG_USER_VIM ?= y
CONFIG_USER_SL ?= y
CONFIG_USER_MAN_PAGES ?= y
CONFIG_USER_MAN_DB ?= y
CONFIG_USER_WGET ?= y
CONFIG_USER_KERNEL_TESTS ?= y

ifeq ($(CONFIG_KERNEL_WERROR),y)
CFLAGS += -Werror
endif

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
USER_LESS := $(BUILD_DIR)/userspace/less
USER_VIM := $(BUILD_DIR)/userspace/vim
USER_MAN_PAGES := $(BUILD_DIR)/userspace/man-pages
USER_LIBPIPELINE := $(BUILD_DIR)/userspace/libpipeline
USER_GDBM := $(BUILD_DIR)/userspace/gdbm
USER_GROFF := $(BUILD_DIR)/userspace/groff
USER_MAN_DB := $(BUILD_DIR)/userspace/man-db
USER_GMP := $(BUILD_DIR)/userspace/gmp
USER_NETTLE := $(BUILD_DIR)/userspace/nettle
USER_GNUTLS := $(BUILD_DIR)/userspace/gnutls
USER_WGET := $(BUILD_DIR)/userspace/wget
USER_TESTS := $(BUILD_DIR)/userspace/kernel-tests-root
KMALLOC_HOST_TEST := $(BUILD_DIR)/tests/kmalloc-host-test
HOST_TEST_ZIG_GLOBAL_CACHE := $(abspath $(BUILD_DIR)/zig-global-cache)
HOST_TEST_ZIG_LOCAL_CACHE := $(abspath $(BUILD_DIR)/zig-local-cache)
BASH_SRC := external/bash-src
NCURSES_SRC := external/ncurses-src
NCURSES_BUILD := $(NCURSES_SRC)/build-musl
GNUTLS_SRC := external/gnutls-src
GMP_TARBALL := /var/cache/distfiles/gmp-6.3.0.tar.xz
NETTLE_TARBALL := /var/cache/distfiles/nettle-3.10.2.tar.gz
SL_SRC := external/sl-src
FILE_SRC := external/file-src
NANO_SRC := external/nano-src
LESS_SRC := external/less-src
VIM_SRC := external/vim-src
WGET_SRC := external/wget-src
MAN_PAGES_SRC := external/man-pages-src
LIBPIPELINE_SRC := external/libpipeline-src
GDBM_SRC := external/gdbm-src
GROFF_SRC := external/groff-src
MAN_DB_SRC := external/man-db-src
CA_CERT_BUNDLE ?= /etc/ssl/certs/ca-certificates.crt
USER_SL := $(BUILD_DIR)/userspace/sl
HELP_SRC := userspace/help.c
TESTS_SRC := $(shell find tests -type f | sort)
LESS_SRC_FILES := $(shell find $(LESS_SRC) -path "$(LESS_SRC)/build-musl" -prune -o -type f -print | sort)
VIM_SRC_FILES := $(shell find $(VIM_SRC) \
	-name build-musl-zigcc-wrapper.sh -prune -o \
	-path "$(VIM_SRC)/src/objects" -prune -o \
	-name vim -prune -o \
	-path "$(VIM_SRC)/src/auto/config.cache" -prune -o \
	-path "$(VIM_SRC)/src/auto/config.h" -prune -o \
	-path "$(VIM_SRC)/src/auto/config.log" -prune -o \
	-path "$(VIM_SRC)/src/auto/config.mk" -prune -o \
	-path "$(VIM_SRC)/src/auto/config.status" -prune -o \
	-path "$(VIM_SRC)/src/auto/osdef.h" -prune -o \
	-path "$(VIM_SRC)/src/auto/pathdef.c" -prune -o \
	-name '*.log' -prune -o \
	-type f -print | sort)
WGET_SRC_FILES := $(shell find $(WGET_SRC) -path "$(WGET_SRC)/build-musl" -prune -o -type f -print | sort)

export STRIP_BINARIES := $(if $(filter y,$(CONFIG_STRIP_BINARIES)),1,0)
export STRIP

.PHONY: all clean run iso disk docs check check-kmalloc check-toolchain check-build-tools check-image-tools \
	check-iso-tools check-disk-tools check-run-tools all-debug iso-debug disk-debug run-debug \
	config oldconfig menuconfig defconfig olddefconfig savedefconfig

all: disk

all-debug: export STRIP_BINARIES := 0
all-debug: all

iso-debug: export STRIP_BINARIES := 0
iso-debug: iso

disk-debug: export STRIP_BINARIES := 0
disk-debug: disk

run-debug: export STRIP_BINARIES := 0
run-debug: run

check-build-tools:
	@command -v python3 >/dev/null
	@command -v $(CC) >/dev/null
	@command -v $(HOST_CC) >/dev/null
	@command -v $(LD) >/dev/null
	@command -v $(NASM) >/dev/null
	@if [[ "$(STRIP_BINARIES)" != "0" ]]; then command -v $(STRIP) >/dev/null; fi
	@command -v zig >/dev/null
	@command -v readelf >/dev/null

check-image-tools: check-build-tools
	@command -v cpio >/dev/null
	@command -v mkfs.ext3 >/dev/null
	@command -v tic >/dev/null

check-iso-tools: check-image-tools
	@command -v grub-mkrescue >/dev/null
	@command -v xorriso >/dev/null
	@command -v mformat >/dev/null

check-disk-tools: check-image-tools
	@command -v grub-mkimage >/dev/null
	@command -v parted >/dev/null

check-run-tools:
	@command -v qemu-system-x86_64 >/dev/null

check-toolchain: check-iso-tools check-disk-tools check-run-tools

check: check-kmalloc

check-kmalloc: $(KMALLOC_HOST_TEST)
	$<

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(CONFIG_FILE): $(KCONFIG_TOOL) $(KCONFIG)
	$(KCONFIG_TOOL) olddefconfig --kconfig $(KCONFIG) --config $@

$(CONFIG_MK) $(CONFIG_HEADER): $(KCONFIG_TOOL) $(KCONFIG) $(CONFIG_FILE) | $(BUILD_DIR)
	$(KCONFIG_TOOL) sync --kconfig $(KCONFIG) --config $(CONFIG_FILE) --out-mk $(CONFIG_MK) --out-header $(CONFIG_HEADER)

$(MENUCONFIG): tools/menuconfig.c | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(HOST_CC) -Wall -Wextra -O2 $(NCURSES_CFLAGS) -o $@ $< $(NCURSES_LIBS)

config: $(KCONFIG_TOOL) $(KCONFIG)
	$(KCONFIG_TOOL) config --kconfig $(KCONFIG) --config $(CONFIG_FILE)
	$(KCONFIG_TOOL) sync --kconfig $(KCONFIG) --config $(CONFIG_FILE) --out-mk $(CONFIG_MK) --out-header $(CONFIG_HEADER)

oldconfig: $(KCONFIG_TOOL) $(KCONFIG)
	$(KCONFIG_TOOL) oldconfig --kconfig $(KCONFIG) --config $(CONFIG_FILE)
	$(KCONFIG_TOOL) sync --kconfig $(KCONFIG) --config $(CONFIG_FILE) --out-mk $(CONFIG_MK) --out-header $(CONFIG_HEADER)

menuconfig: $(MENUCONFIG) $(KCONFIG_TOOL) $(KCONFIG)
	$(MENUCONFIG) --kconfig $(KCONFIG) --config $(CONFIG_FILE)
	$(KCONFIG_TOOL) sync --kconfig $(KCONFIG) --config $(CONFIG_FILE) --out-mk $(CONFIG_MK) --out-header $(CONFIG_HEADER)

defconfig: $(KCONFIG_TOOL) $(KCONFIG)
	$(KCONFIG_TOOL) defconfig --kconfig $(KCONFIG) --config $(CONFIG_FILE)
	$(KCONFIG_TOOL) sync --kconfig $(KCONFIG) --config $(CONFIG_FILE) --out-mk $(CONFIG_MK) --out-header $(CONFIG_HEADER)

olddefconfig: $(KCONFIG_TOOL) $(KCONFIG)
	$(KCONFIG_TOOL) olddefconfig --kconfig $(KCONFIG) --config $(CONFIG_FILE)
	$(KCONFIG_TOOL) sync --kconfig $(KCONFIG) --config $(CONFIG_FILE) --out-mk $(CONFIG_MK) --out-header $(CONFIG_HEADER)

savedefconfig: $(KCONFIG_TOOL) $(KCONFIG) $(CONFIG_FILE)
	$(KCONFIG_TOOL) savedefconfig --kconfig $(KCONFIG) --config $(CONFIG_FILE) --output defconfig

$(DOCS_OUT):
	@mkdir -p $(DOCS_OUT)

$(BUILD_DIR)/kernel/boot/%.o: kernel/boot/%.asm | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(NASM) -f elf64 $< -o $@

$(BUILD_DIR)/kernel/src/%.o: kernel/src/%.c $(CONFIG_HEADER) | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(KMALLOC_HOST_TEST): tests/kmalloc-host-test.c kernel/src/kmalloc.c kernel/include/kmalloc.h | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	ZIG_GLOBAL_CACHE_DIR="$(HOST_TEST_ZIG_GLOBAL_CACHE)" \
	ZIG_LOCAL_CACHE_DIR="$(HOST_TEST_ZIG_LOCAL_CACHE)" \
	zig cc -target x86_64-linux-musl -static -no-pie -std=gnu11 -Wall -Wextra -Werror \
		-Ikernel/include -o $@ $<

$(KERNEL_BIN): $(KERNEL_OBJS) kernel/linker.ld | $(BUILD_DIR)
	$(LD) $(LDFLAGS) -o $@ $(KERNEL_OBJS)
	@if [[ "$(STRIP_BINARIES)" != "0" ]]; then $(STRIP) $@; fi

$(USER_BUSYBOX): tools/build_busybox.sh $(CONFIG_MK) | $(BUILD_DIR)
	./tools/build_busybox.sh $@ "$(BUSYBOX_SRC)" "$(BUSYBOX_STATIC)" "$(BUSYBOX_ROOTFS)"

$(USER_COREUTILS): $(CONFIG_MK) | $(BUILD_DIR)
	./tools/build_coreutils.sh $@ "$(USER_COREUTILS_PROGS)" "$(COREUTILS_SRC)"

$(USER_COREUTILS_PROGS): $(USER_COREUTILS)
	@test -f "$@"

$(USER_BASH): $(NCURSES_BUILD)/lib/libncursesw.a $(CONFIG_MK) | $(BUILD_DIR)
	./tools/build_bash.sh $@ "$(BASH_SRC)"

$(NCURSES_BUILD)/lib/libncursesw.a: | $(BUILD_DIR)
	./tools/build_ncurses.sh $@ "$(NCURSES_SRC)"

$(USER_SL): $(NCURSES_BUILD)/lib/libncursesw.a $(CONFIG_MK) | $(BUILD_DIR)
	./tools/build_sl.sh $@ "$(SL_SRC)" "$(NCURSES_BUILD)"

$(USER_HELP): $(HELP_SRC) $(CONFIG_MK) | $(BUILD_DIR)
	./tools/build_help.sh $@ "$(HELP_SRC)"

$(USER_FILE): $(CONFIG_MK) | $(BUILD_DIR)
	./tools/build_file.sh $@ "$(USER_FILE_MAGIC)" "$(FILE_SRC)"

$(USER_FILE_MAGIC): $(USER_FILE)
	@test -f "$@"

$(USER_NANO): $(NCURSES_BUILD)/lib/libncursesw.a $(CONFIG_MK) | $(BUILD_DIR)
	./tools/build_nano.sh $@ "$(NANO_SRC)"

$(USER_LESS): $(NCURSES_BUILD)/lib/libncursesw.a $(LESS_SRC_FILES) tools/build_less.sh $(CONFIG_MK) | $(BUILD_DIR)
	./tools/build_less.sh $@ "$(LESS_SRC)" "$(NCURSES_BUILD)"

$(USER_VIM): $(NCURSES_BUILD)/lib/libncursesw.a $(VIM_SRC_FILES) tools/build_vim.sh $(CONFIG_MK) | $(BUILD_DIR)
	./tools/build_vim.sh $@ "$(VIM_SRC)" "$(NCURSES_BUILD)"

$(USER_MAN_PAGES): $(CONFIG_MK) | $(BUILD_DIR)
	./tools/build_man_pages.sh $@ "$(MAN_PAGES_SRC)"

$(USER_LIBPIPELINE): $(CONFIG_MK) | $(BUILD_DIR)
	./tools/build_libpipeline.sh $@ "$(LIBPIPELINE_SRC)"

$(USER_GDBM): $(CONFIG_MK) | $(BUILD_DIR)
	./tools/build_gdbm.sh $@ "$(GDBM_SRC)"

$(USER_GROFF): $(CONFIG_MK) | $(BUILD_DIR)
	./tools/build_groff.sh $@ "$(GROFF_SRC)"

$(USER_MAN_DB): $(USER_LIBPIPELINE) $(USER_GDBM) $(USER_GROFF) tools/build_man_db.sh | $(BUILD_DIR)
	./tools/build_man_db.sh $@ "$(MAN_DB_SRC)" "$(USER_LIBPIPELINE)" "$(USER_GDBM)" "$(USER_GROFF)"

$(USER_GMP): tools/build_gmp.sh $(GMP_TARBALL) $(CONFIG_MK) | $(BUILD_DIR)
	./tools/build_gmp.sh $@ "$(GMP_TARBALL)"

$(USER_NETTLE): $(USER_GMP) tools/build_nettle.sh $(NETTLE_TARBALL) $(CONFIG_MK) | $(BUILD_DIR)
	./tools/build_nettle.sh $@ "$(NETTLE_TARBALL)" "$(USER_GMP)"

$(USER_GNUTLS): $(USER_NETTLE) $(USER_GMP) tools/build_gnutls.sh $(CONFIG_MK) | $(BUILD_DIR)
	./tools/build_gnutls.sh $@ "$(GNUTLS_SRC)" "$(USER_NETTLE)" "$(USER_GMP)"

$(USER_WGET): $(USER_GNUTLS) $(USER_NETTLE) $(USER_GMP) $(WGET_SRC_FILES) tools/build_wget.sh $(CA_CERT_BUNDLE) $(CONFIG_MK) | $(BUILD_DIR)
	./tools/build_wget.sh $@ "$(WGET_SRC)" "$(USER_GNUTLS)" "$(USER_NETTLE)" "$(USER_GMP)" "$(CA_CERT_BUNDLE)"

$(USER_TESTS): $(TESTS_SRC) tools/build_kernel_tests.sh $(CONFIG_MK) | $(BUILD_DIR)
	./tools/build_kernel_tests.sh $@ tests

INITRAMFS_DEPS := $(USER_BUSYBOX)
INITRAMFS_ARGS :=
INITRAMFS_BUSYBOX_ARG := $(USER_BUSYBOX)
ifeq ($(CONFIG_USER_HELP),y)
INITRAMFS_DEPS += $(USER_HELP)
INITRAMFS_HELP_ARG := $(USER_HELP)
endif
ifeq ($(CONFIG_USER_COREUTILS),y)
INITRAMFS_DEPS += $(USER_COREUTILS) $(USER_COREUTILS_PROGS)
INITRAMFS_COREUTILS_DIR_ARG := $(USER_COREUTILS)
INITRAMFS_COREUTILS_PROGS_ARG := $(USER_COREUTILS_PROGS)
endif

$(INITRAMFS): tools/make_initramfs.sh $(CONFIG_MK) $(INITRAMFS_DEPS)
	./tools/make_initramfs.sh $@ "$(INITRAMFS_BUSYBOX_ARG)" "$(INITRAMFS_HELP_ARG)" "$(INITRAMFS_COREUTILS_DIR_ARG)" "$(INITRAMFS_COREUTILS_PROGS_ARG)"

USR_DEPS :=
USR_TREE_ARGS :=
ifeq ($(CONFIG_USER_BASH),y)
USR_DEPS += $(USER_BASH)
USR_BASH_ARG := $(USER_BASH)
endif
ifeq ($(CONFIG_USER_HELP),y)
USR_DEPS += $(USER_HELP)
USR_HELP_ARG := $(USER_HELP)
endif
ifeq ($(CONFIG_USER_SL),y)
USR_DEPS += $(USER_SL)
USR_SL_ARG := $(USER_SL)
endif
ifeq ($(CONFIG_USER_FILE),y)
USR_DEPS += $(USER_FILE) $(USER_FILE_MAGIC)
USR_FILE_ARG := $(USER_FILE)
USR_FILE_MAGIC_ARG := $(USER_FILE_MAGIC)
endif
ifeq ($(CONFIG_USER_NANO),y)
USR_DEPS += $(USER_NANO)
USR_NANO_ARG := $(USER_NANO)
endif
ifeq ($(CONFIG_USER_LESS),y)
USR_DEPS += $(USER_LESS)
USR_LESS_ARG := $(USER_LESS)
endif
ifeq ($(CONFIG_USER_COREUTILS),y)
USR_DEPS += $(USER_COREUTILS) $(USER_COREUTILS_PROGS)
USR_COREUTILS_DIR_ARG := $(USER_COREUTILS)
USR_COREUTILS_PROGS_ARG := $(USER_COREUTILS_PROGS)
endif
ifeq ($(CONFIG_USER_MAN_PAGES),y)
USR_DEPS += $(USER_MAN_PAGES)
USR_TREE_ARGS += $(USER_MAN_PAGES)
endif
ifeq ($(CONFIG_USER_MAN_DB),y)
USR_DEPS += $(USER_GROFF) $(USER_MAN_DB)
USR_TREE_ARGS += $(USER_GROFF) $(USER_MAN_DB)
endif
ifeq ($(CONFIG_USER_WGET),y)
USR_DEPS += $(USER_WGET)
USR_TREE_ARGS += $(USER_WGET)
endif
ifeq ($(CONFIG_USER_KERNEL_TESTS),y)
USR_DEPS += $(USER_TESTS)
USR_TREE_ARGS += $(USER_TESTS)
endif
ifeq ($(CONFIG_USER_VIM),y)
USR_DEPS += $(USER_VIM)
USR_TREE_ARGS += $(USER_VIM)
endif

$(USR_EXT3): tools/make_usr_ext2.sh $(CONFIG_MK) $(USR_DEPS)
	./tools/make_usr_ext2.sh $@ "$(USR_BASH_ARG)" "$(USR_HELP_ARG)" "$(USR_SL_ARG)" "$(USR_FILE_ARG)" "$(USR_FILE_MAGIC_ARG)" "$(USR_NANO_ARG)" "$(USR_LESS_ARG)" "$(USR_COREUTILS_DIR_ARG)" "$(USR_COREUTILS_PROGS_ARG)" $(USR_TREE_ARGS)

$(HOME_EXT3): tools/make_home_ext2.sh | $(BUILD_DIR)
	./tools/make_home_ext2.sh $@

iso: check-iso-tools $(KERNEL_BIN) $(INITRAMFS) $(USR_EXT3)
	./tools/make_iso.sh $(ISO_IMAGE) $(KERNEL_BIN) $(INITRAMFS) $(USR_EXT3)

# BIOS + GPT raw disk image, built without loop devices or root privileges.
disk: check-disk-tools $(KERNEL_BIN) $(INITRAMFS) $(USR_EXT3) $(HOME_EXT3)
	./tools/make_gpt_disk.sh $(DISK_IMAGE) $(KERNEL_BIN) $(INITRAMFS) $(USR_EXT3)

run: check-run-tools disk $(USR_EXT3) $(HOME_EXT3)
	qemu-system-x86_64 \
		-machine q35,accel=kvm:tcg \
		-m 1G \
		-vga none \
		-device virtio-vga \
		-drive format=raw,file=$(DISK_IMAGE),if=ide,index=0 \
		-device virtio-scsi-pci-transitional,id=scsi0 \
		-drive format=raw,file=$(USR_EXT3),if=none,id=usr \
		-device scsi-hd,drive=usr,bus=scsi0.0,scsi-id=0,lun=0 \
		-drive format=raw,file=$(HOME_EXT3),if=none,id=home \
		-device scsi-hd,drive=home,bus=scsi0.0,scsi-id=1,lun=0 \
		-netdev user,id=net0 \
		-device virtio-net-pci-transitional,netdev=net0 \
		-chardev stdio,id=serial0,signal=off \
		-serial chardev:serial0

docs: $(DOCS_SRC) | $(DOCS_OUT)
	rm -rf $(DOCS_HTML_SPLIT) $(DOCS_PDF_BUILD)
	texi2any --no-split --output=$(DOCS_INFO) $(DOCS_SRC)
	texi2any --html --no-split --output=$(DOCS_HTML) $(DOCS_SRC)
	texi2any --html --split=node --output=$(DOCS_HTML_SPLIT) $(DOCS_SRC)
	texi2pdf --quiet --build=clean --build-dir=$(DOCS_PDF_BUILD) --output=$(DOCS_PDF) $(DOCS_SRC)

clean:
	rm -rf $(BUILD_DIR) $(DOCS_OUT) $(ZIG_GLOBAL_CACHE) $(ZIG_LOCAL_CACHE) $(COREUTILS_ZIG_GLOBAL_CACHE) $(COREUTILS_ZIG_LOCAL_CACHE) $(GNUTLS_SRC)/build-musl $(WGET_SRC)/build-musl
