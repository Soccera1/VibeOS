SHELL := /bin/bash

BUILD_DIR := build
KCONFIG := Kconfig
CONFIG_FILE := .config
KCONFIG_TOOL := $(BUILD_DIR)/tools/kconfig
DCONFIG := $(BUILD_DIR)/tools/dconfig
TCONFIG := $(BUILD_DIR)/tools/tconfig
MENUCONFIG := $(BUILD_DIR)/tools/menuconfig
GCONFIG := $(BUILD_DIR)/tools/gconfig
ACONFIG := $(BUILD_DIR)/tools/aconfig
G4CONFIG := $(BUILD_DIR)/tools/g4config
G2CONFIG := $(BUILD_DIR)/tools/g2config
XCONFIG := $(BUILD_DIR)/tools/xconfig
FCONFIG := $(BUILD_DIR)/tools/fconfig
TKCONFIG := $(BUILD_DIR)/tools/tkconfig
MCONFIG := $(BUILD_DIR)/tools/mconfig
# Plain C host tools prefer static musl; GUI and ncurses use host glibc libraries.
CONFIG_LINK ?= static
CONFIG_MK := $(BUILD_DIR)/config.mk
CONFIG_HEADER := $(BUILD_DIR)/include/generated/autoconf.h
KERNEL_BIN := $(BUILD_DIR)/vibeos-kernel.bin
INITRAMFS := $(BUILD_DIR)/initramfs.cpio
USR_XFS := $(BUILD_DIR)/usr.xfs
HOME_XFS := $(BUILD_DIR)/home.xfs
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
HOST_CXX ?= c++
GLIBC_CC ?= gcc
PKG_CONFIG ?= pkg-config
FLTK_CONFIG ?= fltk-config
MOTIF_CFLAGS ?=
MOTIF_LIBS ?= -lXm -lXt -lX11
# Static userspace is always musl; these do not change kernel or glibc compilers.
export MUSL_CC MUSL_CXX MUSL_AR MUSL_RANLIB
MUSL_TOOL := $(abspath tools/musl_toolchain.sh)
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

CONFIG_GOALS := config-tools check-dconfig check-tconfig check-config check-guiconfig check-g2config check-g4config check-aconfig check-fconfig check-tkconfig check-mconfig check-kernel-config config oldconfig dconfig tconfig menuconfig xconfig fconfig tkconfig mconfig gconfig g3config g2config g4config aconfig defconfig olddefconfig savedefconfig clean
ifeq ($(filter $(CONFIG_GOALS),$(MAKECMDGOALS)),)
-include $(CONFIG_MK)
endif

CONFIG_STRIP_BINARIES ?= y
CONFIG_KERNEL_WERROR ?= y
CONFIG_KERNEL_DEBUG_INFO ?= n
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
CONFIG_USER_GLIBC_DYNAMIC ?= y
CONFIG_USER_X11 ?= y

ifeq ($(CONFIG_KERNEL_WERROR),y)
CFLAGS += -Werror
endif

ifeq ($(CONFIG_KERNEL_DEBUG_INFO),y)
CFLAGS += -g
NASM_DEBUG_FLAGS := -g -F dwarf
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
GLIBC_RUNTIME := $(BUILD_DIR)/userspace/glibc-runtime
USER_X11 := $(BUILD_DIR)/userspace/x11
KMALLOC_HOST_TEST := $(BUILD_DIR)/tests/kmalloc-host-test
CONSOLE_REFLOW_HOST_TEST := $(BUILD_DIR)/tests/console-reflow-host-test
ELF_LOADER_HOST_TEST := $(BUILD_DIR)/tests/elf-loader-host-test
HOST_TEST_ZIG_GLOBAL_CACHE := $(abspath $(BUILD_DIR)/zig-global-cache)
HOST_TEST_ZIG_LOCAL_CACHE := $(abspath $(BUILD_DIR)/zig-local-cache)
BASH_SRC := external/bash-src
NCURSES_SRC := external/ncurses-src
NCURSES_BUILD := $(NCURSES_SRC)/build-musl
GNUTLS_SRC := external/gnutls-src
GMP_TARBALL := /var/cache/distfiles/gmp-6.3.0.tar.xz
GLIBC_SRC := external/glibc-src
GLIBC_BUILD_ROOT := $(BUILD_DIR)/glibc-baseline
NETTLE_TARBALL := /var/cache/distfiles/nettle-3.10.2.tar.gz
SL_SRC := external/sl-src
FILE_SRC := external/file-src
NANO_SRC := external/nano-src
LESS_SRC := external/less-src
VIM_SRC := external/vim-src
WGET_SRC := external/wget-src
MAN_PAGES_SRC := external/man-pages-src
MAN_PAGES_OVERLAY := tools/man-pages-vibeos
LIBPIPELINE_SRC := external/libpipeline-src
GDBM_SRC := external/gdbm-src
GROFF_SRC := external/groff-src
MAN_DB_SRC := external/man-db-src
CA_CERT_BUNDLE ?= /etc/ssl/certs/ca-certificates.crt
X11_EXTERNAL_DIR := external
X11_SRC_NAMES := xorgproto xtrans libXau libXdmcp xcb-proto libxcb libX11 libXext \
	libXrender libICE libSM libXt libXmu libXpm libXaw libXinerama termcap zlib \
	libmd pixman freetype expat fontconfig libXft libfontenc libXfont2 libxkbfile \
	xkbcomp xkeyboard-config font-util font-misc-misc xlibre xinit xterm st
X11_SRC_DIRS := $(addprefix $(X11_EXTERNAL_DIR)/,$(addsuffix -src,$(X11_SRC_NAMES)))
X11_SRC_FILES := $(shell find $(X11_SRC_DIRS) \
	-path '*/.gitlab' -prune -o \
	-path 'external/termcap-src/termcap.info' -prune -o \
	-type f -print | sort)
USER_SL := $(BUILD_DIR)/userspace/sl
HELP_SRC := userspace/help.c
KERNEL_TESTS_SRC := tests/kernel-tests.c tests/kernel-test-helper.c tests/glibc-dynamic-helper.c
LESS_SRC_FILES := $(shell find $(LESS_SRC) -path "$(LESS_SRC)/build-musl" -prune -o -type f -print | sort)
VIM_SRC_FILES := $(shell find $(VIM_SRC) \
	\( -name build-musl-zigcc-wrapper.sh -o -name build-musl-muslcc-wrapper.sh \) -prune -o \
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

.PHONY: all clean run iso disk docs check check-kmalloc check-console-reflow check-elf-loader check-glibc-runtime check-glibc-system check-preemption-system check-toolchain check-build-tools check-image-tools \
	check-iso-tools check-disk-tools check-run-tools all-debug iso-debug disk-debug run-debug \
	config oldconfig dconfig tconfig menuconfig xconfig fconfig tkconfig mconfig gconfig g3config g2config g4config aconfig defconfig olddefconfig savedefconfig check-kernel-config

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
	@$(MUSL_TOOL) check $(if $(filter y,$(CONFIG_USER_MAN_DB)),c++,)
	@command -v readelf >/dev/null
	@if [[ "$(CONFIG_USER_X11)" == "y" ]]; then command -v meson >/dev/null; command -v ninja >/dev/null; command -v pkg-config >/dev/null; command -v gperf >/dev/null; command -v tic >/dev/null; fi

check-image-tools: check-build-tools
	@command -v cpio >/dev/null
	@command -v mkfs.ext3 >/dev/null
	@command -v mkfs.xfs >/dev/null
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

check: check-config check-storage-flush check-xfs check-xfs-write check-kmalloc check-console-reflow check-elf-loader check-glibc-runtime check-kernel-config

check-kernel-config: $(BUILD_DIR)/tools/check-kernel-config
	$<

check-kmalloc: $(KMALLOC_HOST_TEST)
	$<

check-console-reflow: $(CONSOLE_REFLOW_HOST_TEST)
	$<

check-elf-loader: $(ELF_LOADER_HOST_TEST)
	$<

check-glibc-runtime: $(GLIBC_RUNTIME) $(USER_TESTS)
	GLIBC_DYNAMIC_TEST=present GLIBC_DYNAMIC_ALLOW_ZERO_BASE=1 \
		$(GLIBC_RUNTIME)/root/lib64/ld-linux-x86-64.so.2 \
		--library-path $(GLIBC_RUNTIME)/usr/lib64 \
		$(USER_TESTS)/libexec/kernel-tests/glibc-dynamic-helper argument

check-preemption-system: disk
	./tools/check_glibc_dynamic.py $(DISK_IMAGE) $(USR_XFS) $(HOME_XFS) preemption_and_clocks kernel_preemption kernel_syscall_contention
	QEMU_CPU=qemu64 ./tools/check_glibc_dynamic.py $(DISK_IMAGE) $(USR_XFS) $(HOME_XFS) preemption_and_clocks kernel_preemption kernel_syscall_contention
	KERNEL_TEST_LIBC=glibc ./tools/check_glibc_dynamic.py $(DISK_IMAGE) $(USR_XFS) $(HOME_XFS) preemption_and_clocks kernel_preemption kernel_syscall_contention

check-glibc-system: disk
	./tools/check_glibc_dynamic.py $(DISK_IMAGE) $(USR_XFS) $(HOME_XFS)

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(CONFIG_FILE): $(KCONFIG_TOOL) $(KCONFIG)
	$(KCONFIG_TOOL) olddefconfig --kconfig $(KCONFIG) --config $@

$(CONFIG_MK) $(CONFIG_HEADER): $(KCONFIG_TOOL) $(KCONFIG) $(CONFIG_FILE) | $(BUILD_DIR)
	$(KCONFIG_TOOL) sync --kconfig $(KCONFIG) --config $(CONFIG_FILE) --out-mk $(CONFIG_MK) --out-header $(CONFIG_HEADER)

CONFIG_SOURCES := tools/kconfig_model.c tools/kconfig.h
CONFIG_CFLAGS := -std=gnu11 -Wall -Wextra -Werror -O2
ifeq ($(CONFIG_LINK),static)
CONFIG_CC = $(MUSL_TOOL) cc
CONFIG_LDFLAGS := -static -no-pie
else ifeq ($(CONFIG_LINK),dynamic)
CONFIG_CC = $(HOST_CC)
CONFIG_LDFLAGS :=
else
$(error CONFIG_LINK must be static or dynamic)
endif

.PHONY: config-tools check-dconfig check-tconfig check-config check-guiconfig check-g2config check-g4config check-aconfig check-fconfig check-tkconfig check-mconfig config-tool-force
config-tools: $(DCONFIG) $(TCONFIG) $(KCONFIG_TOOL) $(MENUCONFIG) $(GCONFIG) $(G4CONFIG) $(ACONFIG) $(XCONFIG) $(FCONFIG) $(TKCONFIG) $(MCONFIG) $(BUILD_DIR)/tools/check-kernel-config

# Rebuild when switching CONFIG_LINK, even when both modes were built before.
$(BUILD_DIR)/tools/config-link: config-tool-force
	@mkdir -p $(dir $@)
	@if ! test -f $@ || ! test "$$(cat $@)" = "$(CONFIG_LINK)"; then echo $(CONFIG_LINK) > $@; fi

$(KCONFIG_TOOL): tools/kconfig.c $(CONFIG_SOURCES) $(BUILD_DIR)/tools/config-link
	$(CONFIG_CC) $(CONFIG_CFLAGS) $(CONFIG_LDFLAGS) -o $@ $< tools/kconfig_model.c

$(DCONFIG): tools/dconfig.c tools/config_editor.c tools/config_editor.h $(CONFIG_SOURCES) $(BUILD_DIR)/tools/config-link
	$(CONFIG_CC) $(CONFIG_CFLAGS) $(CONFIG_LDFLAGS) -o $@ $< tools/config_editor.c tools/kconfig_model.c

$(TCONFIG): tools/tconfig.c tools/config_editor.c tools/config_editor.h $(CONFIG_SOURCES) $(BUILD_DIR)/tools/config-link
	$(CONFIG_CC) $(CONFIG_CFLAGS) $(CONFIG_LDFLAGS) -o $@ $< tools/config_editor.c tools/kconfig_model.c

$(BUILD_DIR)/tools/check-kernel-config: tools/check_kernel_config.c $(CONFIG_SOURCES) $(BUILD_DIR)/tools/config-link
	$(CONFIG_CC) $(CONFIG_CFLAGS) $(CONFIG_LDFLAGS) -o $@ $< tools/kconfig_model.c

$(BUILD_DIR)/tools/kconfig_model.o: $(CONFIG_SOURCES)
	@mkdir -p $(dir $@)
	$(HOST_CC) $(CONFIG_CFLAGS) -c tools/kconfig_model.c -o $@

$(BUILD_DIR)/tools/config_editor.o: tools/config_editor.c tools/config_editor.h tools/kconfig.h
	@mkdir -p $(dir $@)
	$(HOST_CC) $(CONFIG_CFLAGS) -c $< -o $@

CONFIG_EDITOR_OBJS := $(BUILD_DIR)/tools/kconfig_model.o $(BUILD_DIR)/tools/config_editor.o

# g3config disables all fallback, including when multiple GTK targets are requested.
GCONFIG_ALLOW_FALLBACK := $(if $(filter g3config,$(MAKECMDGOALS)),no,yes)
GCONFIG_PKG = $(shell if $(PKG_CONFIG) --exists gtk+-3.0; then echo gtk+-3.0; elif test "$(GCONFIG_ALLOW_FALLBACK)" = yes && $(PKG_CONFIG) --exists libadwaita-1; then echo libadwaita-1; elif test "$(GCONFIG_ALLOW_FALLBACK)" = yes && $(PKG_CONFIG) --exists gtk4; then echo gtk4; elif test "$(GCONFIG_ALLOW_FALLBACK)" = yes && $(PKG_CONFIG) --exists gtk+-2.0; then echo gtk+-2.0; fi)

GCONFIG_SOURCE = tools/$(if $(filter libadwaita-1,$(GCONFIG_PKG)),aconfig,$(if $(filter gtk4,$(GCONFIG_PKG)),g4config,gconfig)).c
GCONFIG_TEST_SOURCE = tests/$(if $(filter libadwaita-1,$(GCONFIG_PKG)),aconfig,$(if $(filter gtk4,$(GCONFIG_PKG)),g4config,gconfig))-test.c

# Track selection so changes in available GTK versions rebuild the automatic frontend.
$(BUILD_DIR)/tools/gconfig-pkg: config-tool-force
	@mkdir -p $(dir $@)
	@test -n "$(GCONFIG_PKG)" || { echo 'gconfig requires pkg-config and GTK 3$(if $(filter yes,$(GCONFIG_ALLOW_FALLBACK)), or Libadwaita or GTK 4 or GTK 2) development libraries.' >&2; exit 1; }
	@if ! test -f $@ || ! test "$$(cat $@)" = "$(GCONFIG_PKG)"; then echo $(GCONFIG_PKG) > $@; fi

$(GCONFIG): $(GCONFIG_SOURCE) tools/g4config.c tools/config_editor.h $(CONFIG_EDITOR_OBJS) $(BUILD_DIR)/tools/gconfig-pkg
	$(HOST_CC) $(CONFIG_CFLAGS) -Wno-deprecated-declarations $$($(PKG_CONFIG) --cflags $(GCONFIG_PKG)) -o $@ $< $(CONFIG_EDITOR_OBJS) $$($(PKG_CONFIG) --libs $(GCONFIG_PKG))

$(G2CONFIG): tools/gconfig.c tools/config_editor.h $(CONFIG_EDITOR_OBJS)
	@$(PKG_CONFIG) --exists gtk+-2.0 || { echo 'g2config requires pkg-config and GTK 2 development libraries.' >&2; exit 1; }
	$(HOST_CC) $(CONFIG_CFLAGS) -Wno-deprecated-declarations $$($(PKG_CONFIG) --cflags gtk+-2.0) -o $@ $< $(CONFIG_EDITOR_OBJS) $$($(PKG_CONFIG) --libs gtk+-2.0)

$(ACONFIG): tools/aconfig.c tools/g4config.c tools/config_editor.h $(CONFIG_EDITOR_OBJS)
	@$(PKG_CONFIG) --exists libadwaita-1 || { echo 'aconfig requires pkg-config and GTK 4/Libadwaita development libraries (libadwaita-1-dev on Debian/Ubuntu).' >&2; exit 1; }
	$(HOST_CC) $(CONFIG_CFLAGS) -Wno-deprecated-declarations $$($(PKG_CONFIG) --cflags libadwaita-1) -o $@ $< $(CONFIG_EDITOR_OBJS) $$($(PKG_CONFIG) --libs libadwaita-1)

$(G4CONFIG): tools/g4config.c tools/config_editor.h $(CONFIG_EDITOR_OBJS)
	@$(PKG_CONFIG) --exists gtk4 || { echo 'g4config requires pkg-config and GTK 4 development libraries (libgtk-4-dev on Debian/Ubuntu).' >&2; exit 1; }
	$(HOST_CC) $(CONFIG_CFLAGS) -Wno-deprecated-declarations $$($(PKG_CONFIG) --cflags gtk4) -o $@ $< $(CONFIG_EDITOR_OBJS) $$($(PKG_CONFIG) --libs gtk4)

$(XCONFIG): tools/xconfig.cpp tools/config_editor.h $(CONFIG_EDITOR_OBJS)
	@$(PKG_CONFIG) --exists Qt6Widgets || { echo 'xconfig requires Qt 6 Widgets development libraries and pkg-config.' >&2; exit 1; }
	$(HOST_CXX) -fPIC -std=c++17 -Wall -Wextra -Werror -O2 $$($(PKG_CONFIG) --cflags Qt6Widgets) -o $@ $< $(CONFIG_EDITOR_OBJS) $$($(PKG_CONFIG) --libs Qt6Widgets)

$(FCONFIG): tools/fconfig.cpp tools/config_editor.h $(CONFIG_EDITOR_OBJS)
	@$(FLTK_CONFIG) --version >/dev/null 2>&1 || { echo 'fconfig requires FLTK development libraries and fltk-config.' >&2; exit 1; }
	$(HOST_CXX) -std=c++17 -Wall -Wextra -Werror -O2 $$($(FLTK_CONFIG) --cxxflags) -o $@ $< $(CONFIG_EDITOR_OBJS) $$($(FLTK_CONFIG) --ldflags)

$(TKCONFIG): tools/tkconfig.c tools/config_editor.h $(CONFIG_EDITOR_OBJS)
	@$(PKG_CONFIG) --exists tk || { echo 'tkconfig requires Tcl/Tk development libraries and pkg-config (tk-dev on Debian/Ubuntu).' >&2; exit 1; }
	$(HOST_CC) $(CONFIG_CFLAGS) $$($(PKG_CONFIG) --cflags tk) -o $@ $< $(CONFIG_EDITOR_OBJS) $$($(PKG_CONFIG) --libs tk)

# Motif/X11 use the host glibc libraries, like the other graphical editors.
$(MCONFIG): tools/mconfig.c tools/config_editor.h $(CONFIG_EDITOR_OBJS)
	@printf '#include <Xm/Xm.h>\nint main(void) { XtToolkitInitialize(); return XmVersion == 0; }\n' | $(HOST_CC) $(MOTIF_CFLAGS) -x c -o /dev/null - $(MOTIF_LIBS) || { echo 'mconfig requires Motif, Xt and X11 development libraries (libmotif-dev libxt-dev libx11-dev on Debian/Ubuntu). Set MOTIF_CFLAGS and MOTIF_LIBS for alternate paths.' >&2; exit 1; }
	$(HOST_CC) $(CONFIG_CFLAGS) $(MOTIF_CFLAGS) -o $@ $< $(CONFIG_EDITOR_OBJS) $(MOTIF_LIBS)

$(MENUCONFIG): tools/menuconfig.c $(CONFIG_SOURCES) | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(HOST_CC) -Wall -Wextra -O2 $(NCURSES_CFLAGS) -o $@ $< tools/kconfig_model.c $(NCURSES_LIBS)

config: $(KCONFIG_TOOL) $(KCONFIG)
	$(KCONFIG_TOOL) config --kconfig $(KCONFIG) --config $(CONFIG_FILE)
	$(KCONFIG_TOOL) sync --kconfig $(KCONFIG) --config $(CONFIG_FILE) --out-mk $(CONFIG_MK) --out-header $(CONFIG_HEADER)

oldconfig: $(KCONFIG_TOOL) $(KCONFIG)
	$(KCONFIG_TOOL) oldconfig --kconfig $(KCONFIG) --config $(CONFIG_FILE)
	$(KCONFIG_TOOL) sync --kconfig $(KCONFIG) --config $(CONFIG_FILE) --out-mk $(CONFIG_MK) --out-header $(CONFIG_HEADER)

dconfig: $(DCONFIG) $(KCONFIG)
	$(DCONFIG) --kconfig $(KCONFIG) --config $(CONFIG_FILE) --out-mk $(CONFIG_MK) --out-header $(CONFIG_HEADER)

check-dconfig: $(DCONFIG)
	python3 tests/dconfig-test.py $(DCONFIG)

tconfig: $(TCONFIG) $(KCONFIG)
	$(TCONFIG) --kconfig $(KCONFIG) --config $(CONFIG_FILE) --out-mk $(CONFIG_MK) --out-header $(CONFIG_HEADER)

check-tconfig: $(TCONFIG)
	python3 tests/tconfig-test.py $(TCONFIG)

menuconfig: $(MENUCONFIG) $(KCONFIG_TOOL) $(KCONFIG)
	$(MENUCONFIG) --kconfig $(KCONFIG) --config $(CONFIG_FILE)
	$(KCONFIG_TOOL) sync --kconfig $(KCONFIG) --config $(CONFIG_FILE) --out-mk $(CONFIG_MK) --out-header $(CONFIG_HEADER)

xconfig: $(XCONFIG) $(KCONFIG)
	$(XCONFIG) --kconfig $(KCONFIG) --config $(CONFIG_FILE) --out-mk $(CONFIG_MK) --out-header $(CONFIG_HEADER)

fconfig: $(FCONFIG) $(KCONFIG)
	$(FCONFIG) --kconfig $(KCONFIG) --config $(CONFIG_FILE) --out-mk $(CONFIG_MK) --out-header $(CONFIG_HEADER)

tkconfig: $(TKCONFIG) $(KCONFIG)
	$(TKCONFIG) --kconfig $(KCONFIG) --config $(CONFIG_FILE) --out-mk $(CONFIG_MK) --out-header $(CONFIG_HEADER)

mconfig: $(MCONFIG) $(KCONFIG)
	$(MCONFIG) --kconfig $(KCONFIG) --config $(CONFIG_FILE) --out-mk $(CONFIG_MK) --out-header $(CONFIG_HEADER)

gconfig: $(GCONFIG) $(KCONFIG)
	$(GCONFIG) --kconfig $(KCONFIG) --config $(CONFIG_FILE) --out-mk $(CONFIG_MK) --out-header $(CONFIG_HEADER)

aconfig: $(ACONFIG) $(KCONFIG)
	$(ACONFIG) --kconfig $(KCONFIG) --config $(CONFIG_FILE) --out-mk $(CONFIG_MK) --out-header $(CONFIG_HEADER)

g4config: $(G4CONFIG) $(KCONFIG)
	$(G4CONFIG) --kconfig $(KCONFIG) --config $(CONFIG_FILE) --out-mk $(CONFIG_MK) --out-header $(CONFIG_HEADER)

g3config: gconfig

g2config: $(G2CONFIG) $(KCONFIG)
	$(G2CONFIG) --kconfig $(KCONFIG) --config $(CONFIG_FILE) --out-mk $(CONFIG_MK) --out-header $(CONFIG_HEADER)

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

$(BUILD_DIR)/kernel/boot/%.o: kernel/boot/%.asm $(CONFIG_HEADER) | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(NASM) $(NASM_DEBUG_FLAGS) -f elf64 $< -o $@

$(BUILD_DIR)/kernel/src/%.o: kernel/src/%.c $(wildcard kernel/include/*.h) $(CONFIG_HEADER) | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(KMALLOC_HOST_TEST): tests/kmalloc-host-test.c kernel/src/kmalloc.c kernel/include/kmalloc.h | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	ZIG_GLOBAL_CACHE_DIR="$(HOST_TEST_ZIG_GLOBAL_CACHE)" \
	ZIG_LOCAL_CACHE_DIR="$(HOST_TEST_ZIG_LOCAL_CACHE)" \
	$(MUSL_TOOL) cc -static -no-pie -std=gnu11 -Wall -Wextra -Werror \
		-Ikernel/include -o $@ $<

$(CONSOLE_REFLOW_HOST_TEST): tests/console-reflow-host-test.c kernel/src/console.c kernel/include/console.h | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	ZIG_GLOBAL_CACHE_DIR="$(HOST_TEST_ZIG_GLOBAL_CACHE)" \
	ZIG_LOCAL_CACHE_DIR="$(HOST_TEST_ZIG_LOCAL_CACHE)" \
	$(MUSL_TOOL) cc -static -no-pie -std=gnu11 -O2 -ffunction-sections -fdata-sections \
		-Wall -Wextra -Werror -Ikernel/include -Wl,--gc-sections -o $@ $<

$(ELF_LOADER_HOST_TEST): tests/elf-loader-host-test.c kernel/src/elf_loader.c kernel/include/elf_loader.h | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	ZIG_GLOBAL_CACHE_DIR="$(HOST_TEST_ZIG_GLOBAL_CACHE)" \
	ZIG_LOCAL_CACHE_DIR="$(HOST_TEST_ZIG_LOCAL_CACHE)" \
	$(MUSL_TOOL) cc -static -no-pie -std=gnu11 -O2 -Wall -Wextra -Werror \
		-Ikernel/include -o $@ tests/elf-loader-host-test.c kernel/src/elf_loader.c

$(KERNEL_BIN): $(KERNEL_OBJS) kernel/linker.ld | $(BUILD_DIR)
	$(LD) $(LDFLAGS) -o $@ $(KERNEL_OBJS)
	@if [[ "$(STRIP_BINARIES)" != "0" && "$(CONFIG_KERNEL_DEBUG_INFO)" != "y" ]]; then $(STRIP) $@; fi

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

$(USER_MAN_PAGES): tools/build_man_pages.sh $(shell find $(MAN_PAGES_OVERLAY) -type f | sort) $(CONFIG_MK) | $(BUILD_DIR)
	./tools/build_man_pages.sh $@ "$(MAN_PAGES_SRC)" "$(MAN_PAGES_OVERLAY)"

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

$(USER_TESTS): $(KERNEL_TESTS_SRC) tools/build_kernel_tests.sh $(CONFIG_MK) | $(BUILD_DIR)
	GLIBC_CC="$(GLIBC_CC)" GLIBC_DYNAMIC_TEST="$(if $(filter y,$(CONFIG_USER_GLIBC_DYNAMIC)),1,0)" \
		./tools/build_kernel_tests.sh $@ tests

$(GLIBC_RUNTIME): tools/build_glibc_runtime.sh userspace/glibc_popcount.c $(GLIBC_SRC)/configure $(CONFIG_MK) | $(BUILD_DIR)
	./tools/build_glibc_runtime.sh $@ "$(GLIBC_SRC)" "$(GLIBC_BUILD_ROOT)"

$(USER_X11): $(GLIBC_RUNTIME) $(X11_SRC_FILES) tools/build_x11.sh tools/patches/xlibre-vibeos-no-epoll.patch \
	tools/patches/xlibre-vibeos-baseline-libgcc.patch tools/patches/xlibre-vibeos-precompiled-xkb.patch \
	tools/patches/xlibre-vibeos-vt-property.patch $(wildcard tools/patches/termcap/*.patch) \
	$(wildcard tools/patches/st/*.patch) userspace/glibc_popcount.c userspace/xhello.c $(CONFIG_MK) | $(BUILD_DIR)
	./tools/build_x11.sh $@ "$(X11_EXTERNAL_DIR)"

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
ifeq ($(CONFIG_USER_GLIBC_DYNAMIC),y)
INITRAMFS_DEPS += $(GLIBC_RUNTIME)
INITRAMFS_GLIBC_ROOT_ARG := $(GLIBC_RUNTIME)/root
endif

$(INITRAMFS): tools/make_initramfs.sh $(CONFIG_MK) $(INITRAMFS_DEPS)
	./tools/make_initramfs.sh $@ "$(INITRAMFS_BUSYBOX_ARG)" "$(INITRAMFS_HELP_ARG)" "$(INITRAMFS_COREUTILS_DIR_ARG)" "$(INITRAMFS_COREUTILS_PROGS_ARG)" "$(INITRAMFS_GLIBC_ROOT_ARG)"

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
ifeq ($(CONFIG_USER_GLIBC_DYNAMIC),y)
USR_DEPS += $(GLIBC_RUNTIME)
USR_TREE_ARGS += $(GLIBC_RUNTIME)/usr
endif
ifeq ($(CONFIG_USER_X11),y)
ifneq ($(CONFIG_USER_GLIBC_DYNAMIC),y)
$(error CONFIG_USER_X11 requires CONFIG_USER_GLIBC_DYNAMIC)
endif
USR_DEPS += $(USER_X11)
USR_TREE_ARGS += $(USER_X11)
endif
ifeq ($(CONFIG_USER_VIM),y)
USR_DEPS += $(USER_VIM)
USR_TREE_ARGS += $(USER_VIM)
endif

$(USR_XFS): tools/make_usr_xfs.sh tools/make_xfs_image.py $(CONFIG_MK) $(USR_DEPS)
	./tools/make_usr_xfs.sh $@ "$(USR_BASH_ARG)" "$(USR_HELP_ARG)" "$(USR_SL_ARG)" "$(USR_FILE_ARG)" "$(USR_FILE_MAGIC_ARG)" "$(USR_NANO_ARG)" "$(USR_LESS_ARG)" "$(USR_COREUTILS_DIR_ARG)" "$(USR_COREUTILS_PROGS_ARG)" $(USR_TREE_ARGS)

$(HOME_XFS): tools/make_home_xfs.sh tools/make_xfs_image.py | $(BUILD_DIR)
	./tools/make_home_xfs.sh $@

iso: check-iso-tools $(KERNEL_BIN) $(INITRAMFS) $(USR_XFS)
	./tools/make_iso.sh $(ISO_IMAGE) $(KERNEL_BIN) $(INITRAMFS) $(USR_XFS)

# BIOS + GPT raw disk image, built without loop devices or root privileges.
disk: check-disk-tools $(KERNEL_BIN) $(INITRAMFS) $(USR_XFS) $(HOME_XFS)
	./tools/make_gpt_disk.sh $(DISK_IMAGE) $(KERNEL_BIN) $(INITRAMFS) $(USR_XFS)

run: check-run-tools disk $(USR_XFS) $(HOME_XFS)
	qemu-system-x86_64 \
		-machine q35,accel=kvm:tcg \
		-m 1G \
		-vga none \
		-device virtio-vga \
		-drive format=raw,file=$(DISK_IMAGE),if=ide,index=0 \
		-device virtio-scsi-pci-transitional,id=scsi0 \
		-drive format=raw,file=$(USR_XFS),if=none,id=usr \
		-device scsi-hd,drive=usr,bus=scsi0.0,scsi-id=0,lun=0 \
		-drive format=raw,file=$(HOME_XFS),if=none,id=home \
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

.PHONY: check-xfs
check-xfs: $(BUILD_DIR)/tests/xfs-host-test $(BUILD_DIR)/tests/xfs-unit-host-test $(BUILD_DIR)/tests/xfs-disabled-host-test
	$(BUILD_DIR)/tests/xfs-unit-host-test
	$(BUILD_DIR)/tests/xfs-disabled-host-test
	python3 tools/check_xfs.py $<
	python3 tools/check_xfs_image.py

$(BUILD_DIR)/tests/xfs-host-test: tests/xfs-host-test.c kernel/src/xfs.c kernel/src/fs.c kernel/src/ext2.c kernel/src/initramfs.c $(wildcard kernel/include/*.h) | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	ZIG_GLOBAL_CACHE_DIR="$(HOST_TEST_ZIG_GLOBAL_CACHE)" \
	ZIG_LOCAL_CACHE_DIR="$(HOST_TEST_ZIG_LOCAL_CACHE)" \
	$(MUSL_TOOL) cc -static -no-pie -std=gnu11 -O2 -ffunction-sections -fdata-sections \
		-Wall -Wextra -Werror -Ikernel/include -DCONFIG_KERNEL_XFS -DCONFIG_KERNEL_EXT2 -DCONFIG_KERNEL_EXT2_WRITE \
		-Wl,--gc-sections -o $@ $(filter %.c,$^)

$(BUILD_DIR)/tests/xfs-unit-host-test $(BUILD_DIR)/tests/xfs-disabled-host-test: tests/xfs-unit-host-test.c kernel/src/xfs.c $(wildcard kernel/include/*.h) | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	ZIG_GLOBAL_CACHE_DIR="$(HOST_TEST_ZIG_GLOBAL_CACHE)" \
	ZIG_LOCAL_CACHE_DIR="$(HOST_TEST_ZIG_LOCAL_CACHE)" \
	$(MUSL_TOOL) cc -static -no-pie -std=gnu11 -O2 -Wall -Wextra -Werror \
		-Ikernel/include $(if $(findstring disabled,$@),,-DCONFIG_KERNEL_XFS) -o $@ $<

.PHONY: check-scsi-flush
check-scsi-flush: $(BUILD_DIR)/tests/scsi-flush-host-test
	$<

$(BUILD_DIR)/tests/scsi-flush-host-test: tests/scsi-flush-host-test.c kernel/src/scsi.c kernel/include/scsi.h kernel/include/ext2.h | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	ZIG_GLOBAL_CACHE_DIR="$(HOST_TEST_ZIG_GLOBAL_CACHE)" \
	ZIG_LOCAL_CACHE_DIR="$(HOST_TEST_ZIG_LOCAL_CACHE)" \
	$(MUSL_TOOL) cc -static -no-pie -std=gnu11 -O2 -Wall -Wextra -Werror \
		-Ikernel/include -o $@ $(filter %.c,$^)

.PHONY: check-storage-flush
check-storage-flush: check-scsi-flush $(BUILD_DIR)/tests/ata-flush-host-test
	$(BUILD_DIR)/tests/ata-flush-host-test

$(BUILD_DIR)/tests/ata-flush-host-test: tests/ata-flush-host-test.c kernel/src/ata.c $(wildcard kernel/include/*.h) | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	ZIG_GLOBAL_CACHE_DIR="$(HOST_TEST_ZIG_GLOBAL_CACHE)" \
	ZIG_LOCAL_CACHE_DIR="$(HOST_TEST_ZIG_LOCAL_CACHE)" \
	$(MUSL_TOOL) cc -static -no-pie -std=gnu11 -O2 -Wall -Wextra -Werror \
		-ffunction-sections -fdata-sections -Wl,--gc-sections -Ikernel/include -o $@ $<

$(BUILD_DIR)/kernel/src/xfs.o $(BUILD_DIR)/tests/xfs-host-test $(BUILD_DIR)/tests/xfs-unit-host-test $(BUILD_DIR)/tests/xfs-disabled-host-test: $(wildcard kernel/src/xfs*.inc)

.PHONY: check-xfs-write
check-xfs-write: $(BUILD_DIR)/tests/xfs-write-host-test $(BUILD_DIR)/tests/xfs-allocation-host-test
	python3 tools/check_xfs_write.py $^

$(BUILD_DIR)/tests/xfs-write-host-test: tests/xfs-write-host-test.c kernel/src/xfs.c kernel/src/fs.c kernel/src/ext2.c kernel/src/initramfs.c $(wildcard kernel/include/*.h) $(wildcard kernel/src/xfs*.inc) | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	ZIG_GLOBAL_CACHE_DIR="$(HOST_TEST_ZIG_GLOBAL_CACHE)" \
	ZIG_LOCAL_CACHE_DIR="$(HOST_TEST_ZIG_LOCAL_CACHE)" \
	$(MUSL_TOOL) cc -static -no-pie -std=gnu11 -O2 -ffunction-sections -fdata-sections \
		-Wall -Wextra -Werror -Ikernel/include -DCONFIG_KERNEL_XFS -DCONFIG_KERNEL_XFS_WRITE \
		-DCONFIG_KERNEL_EXT2 -DCONFIG_KERNEL_EXT2_WRITE -Wl,--gc-sections -o $@ $(filter %.c,$^)

$(BUILD_DIR)/tests/xfs-allocation-host-test: tests/xfs-allocation-host-test.c kernel/src/xfs.c $(wildcard kernel/include/*.h) $(wildcard kernel/src/xfs*.inc) | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	ZIG_GLOBAL_CACHE_DIR="$(HOST_TEST_ZIG_GLOBAL_CACHE)" \
	ZIG_LOCAL_CACHE_DIR="$(HOST_TEST_ZIG_LOCAL_CACHE)" \
	$(MUSL_TOOL) cc -static -no-pie -std=gnu11 -O2 -Wall -Wextra -Werror \
		-Ikernel/include -DCONFIG_KERNEL_XFS -DCONFIG_KERNEL_XFS_WRITE -o $@ $<

.PHONY: check-xfs-kernel
check-xfs-kernel: $(KERNEL_BIN) $(INITRAMFS) $(USR_XFS) $(BUILD_DIR)/tests/xfs-kernel-static $(BUILD_DIR)/tests/xfs-kernel-dynamic
	python3 tools/check_xfs_kernel.py $(KERNEL_BIN) $(INITRAMFS) $(USR_XFS) $(BUILD_DIR)/tests/xfs-kernel-static
	python3 tools/check_xfs_kernel.py $(KERNEL_BIN) $(INITRAMFS) $(USR_XFS) $(BUILD_DIR)/tests/xfs-kernel-dynamic

$(BUILD_DIR)/tests/xfs-kernel-static: tests/xfs-kernel-test.c | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	ZIG_GLOBAL_CACHE_DIR="$(HOST_TEST_ZIG_GLOBAL_CACHE)" \
	ZIG_LOCAL_CACHE_DIR="$(HOST_TEST_ZIG_LOCAL_CACHE)" \
	$(MUSL_TOOL) cc -static -std=gnu11 -O2 -Wall -Wextra -Werror -o $@ $<

$(BUILD_DIR)/tests/xfs-kernel-dynamic: tests/xfs-kernel-test.c | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(GLIBC_CC) -std=gnu11 -O2 -Wall -Wextra -Werror -Wl,-rpath,/usr/lib64 -o $@ $<

.PHONY: check-musl-toolchain
check-musl-toolchain:
	$(MUSL_TOOL) check $(if $(filter y,$(CONFIG_USER_MAN_DB)),c++,)
	python3 tests/musl-toolchain-test.py

# The content changes only when the selected tools change. Keep package caches
# and host-test binaries from silently retaining a previous compiler selection.
.PHONY: FORCE_MUSL_TOOLCHAIN
$(BUILD_DIR)/musl-toolchain: FORCE_MUSL_TOOLCHAIN tools/musl_toolchain.sh tools/zig_flags.sh | $(BUILD_DIR)
	@$(MUSL_TOOL) fingerprint > $@.tmp
	@cmp -s $@.tmp $@ && rm $@.tmp || mv $@.tmp $@

$(KMALLOC_HOST_TEST) $(CONSOLE_REFLOW_HOST_TEST) $(ELF_LOADER_HOST_TEST) \
	$(USER_BUSYBOX) $(USER_COREUTILS) $(USER_BASH) \
	$(NCURSES_BUILD)/lib/libncursesw.a $(USER_SL) $(USER_HELP) \
	$(USER_FILE) $(USER_NANO) $(USER_LESS) \
	$(USER_VIM) $(USER_LIBPIPELINE) $(USER_GDBM) \
	$(USER_GROFF) $(USER_MAN_DB) $(USER_GMP) \
	$(USER_NETTLE) $(USER_GNUTLS) $(USER_WGET) \
	$(USER_TESTS) $(BUILD_DIR)/tests/xfs-host-test $(BUILD_DIR)/tests/xfs-unit-host-test \
	$(BUILD_DIR)/tests/xfs-disabled-host-test $(BUILD_DIR)/tests/scsi-flush-host-test $(BUILD_DIR)/tests/ata-flush-host-test \
	$(BUILD_DIR)/tests/xfs-write-host-test $(BUILD_DIR)/tests/xfs-allocation-host-test $(BUILD_DIR)/tests/xfs-kernel-static: $(BUILD_DIR)/musl-toolchain

check-config: $(KCONFIG_TOOL)
	python3 tests/kconfig-test.py $(KCONFIG_TOOL)

$(BUILD_DIR)/tests/gconfig-test: $(GCONFIG_TEST_SOURCE) tests/g4config-test.c tests/config-fixture.h $(GCONFIG_SOURCE) tools/g4config.c tools/config_editor.h $(CONFIG_EDITOR_OBJS) $(BUILD_DIR)/tools/gconfig-pkg
	@mkdir -p $(dir $@)
	$(HOST_CC) $(CONFIG_CFLAGS) -Wno-deprecated-declarations $$($(PKG_CONFIG) --cflags $(GCONFIG_PKG)) -o $@ $< $(CONFIG_EDITOR_OBJS) $$($(PKG_CONFIG) --libs $(GCONFIG_PKG))

$(BUILD_DIR)/tests/g2config-test: tests/gconfig-test.c tests/config-fixture.h tools/gconfig.c tools/config_editor.h $(CONFIG_EDITOR_OBJS)
	@mkdir -p $(dir $@)
	@$(PKG_CONFIG) --exists gtk+-2.0 || { echo 'g2config requires pkg-config and GTK 2 development libraries.' >&2; exit 1; }
	$(HOST_CC) $(CONFIG_CFLAGS) -Wno-deprecated-declarations $$($(PKG_CONFIG) --cflags gtk+-2.0) -o $@ $< $(CONFIG_EDITOR_OBJS) $$($(PKG_CONFIG) --libs gtk+-2.0)

$(BUILD_DIR)/tests/g4config-test: tests/g4config-test.c tests/config-fixture.h tools/g4config.c tools/config_editor.h $(CONFIG_EDITOR_OBJS) $(G4CONFIG)
	@mkdir -p $(dir $@)
	$(HOST_CC) $(CONFIG_CFLAGS) -Wno-deprecated-declarations $$($(PKG_CONFIG) --cflags gtk4) -o $@ $< $(CONFIG_EDITOR_OBJS) $$($(PKG_CONFIG) --libs gtk4)

$(BUILD_DIR)/tests/aconfig-test: tests/aconfig-test.c tests/g4config-test.c tests/config-fixture.h tools/aconfig.c tools/g4config.c tools/config_editor.h $(CONFIG_EDITOR_OBJS) $(ACONFIG)
	@mkdir -p $(dir $@)
	$(HOST_CC) $(CONFIG_CFLAGS) -Wno-deprecated-declarations $$($(PKG_CONFIG) --cflags libadwaita-1) -o $@ $< $(CONFIG_EDITOR_OBJS) $$($(PKG_CONFIG) --libs libadwaita-1)

check-aconfig: $(BUILD_DIR)/tests/aconfig-test
	$(BUILD_DIR)/tests/aconfig-test

check-g4config: $(BUILD_DIR)/tests/g4config-test
	$(BUILD_DIR)/tests/g4config-test

$(BUILD_DIR)/tests/xconfig-test: tests/xconfig-test.cpp tests/config-fixture.h tools/xconfig.cpp tools/config_editor.h $(CONFIG_EDITOR_OBJS)
	@mkdir -p $(dir $@)
	$(HOST_CXX) -fPIC -std=c++17 -Wall -Wextra -Werror -O2 $$($(PKG_CONFIG) --cflags Qt6Widgets) -o $@ $< $(CONFIG_EDITOR_OBJS) $$($(PKG_CONFIG) --libs Qt6Widgets)

# Run under a desktop display or Xvfb; Qt also supports QT_QPA_PLATFORM=offscreen.
check-guiconfig: $(BUILD_DIR)/tests/aconfig-test $(BUILD_DIR)/tests/g4config-test $(BUILD_DIR)/tests/gconfig-test $(BUILD_DIR)/tests/xconfig-test $(BUILD_DIR)/tests/fconfig-test $(BUILD_DIR)/tests/mconfig-test $(BUILD_DIR)/tests/tkconfig-test
	$(BUILD_DIR)/tests/aconfig-test
	$(BUILD_DIR)/tests/gconfig-test
	$(BUILD_DIR)/tests/g4config-test
	$(BUILD_DIR)/tests/xconfig-test
	$(BUILD_DIR)/tests/fconfig-test
	$(BUILD_DIR)/tests/mconfig-test
	$(BUILD_DIR)/tests/tkconfig-test

check-g2config: $(BUILD_DIR)/tests/g2config-test
	$(BUILD_DIR)/tests/g2config-test

$(BUILD_DIR)/tests/fconfig-test: tests/fconfig-test.cpp tests/config-fixture.h tools/fconfig.cpp tools/config_editor.h $(CONFIG_EDITOR_OBJS)
	@mkdir -p $(dir $@)
	@$(FLTK_CONFIG) --version >/dev/null 2>&1 || { echo 'fconfig requires FLTK development libraries and fltk-config.' >&2; exit 1; }
	$(HOST_CXX) -std=c++17 -Wall -Wextra -Werror -O2 $$($(FLTK_CONFIG) --cxxflags) -o $@ $< $(CONFIG_EDITOR_OBJS) $$($(FLTK_CONFIG) --ldflags)

check-fconfig: $(BUILD_DIR)/tests/fconfig-test
	$(BUILD_DIR)/tests/fconfig-test

$(BUILD_DIR)/tests/mconfig-test: tests/mconfig-test.c tests/config-fixture.h tools/mconfig.c tools/config_editor.h $(CONFIG_EDITOR_OBJS) $(MCONFIG)
	@mkdir -p $(dir $@)
	$(HOST_CC) $(CONFIG_CFLAGS) $(MOTIF_CFLAGS) -o $@ $< $(CONFIG_EDITOR_OBJS) $(MOTIF_LIBS)

check-mconfig: $(BUILD_DIR)/tests/mconfig-test
	$(BUILD_DIR)/tests/mconfig-test

$(BUILD_DIR)/tests/tkconfig-test: tests/tkconfig-test.c tests/config-fixture.h tools/tkconfig.c tools/config_editor.h $(CONFIG_EDITOR_OBJS) $(TKCONFIG)
	@mkdir -p $(dir $@)
	$(HOST_CC) $(CONFIG_CFLAGS) $$($(PKG_CONFIG) --cflags tk) -o $@ $< $(CONFIG_EDITOR_OBJS) $$($(PKG_CONFIG) --libs tk)

check-tkconfig: $(BUILD_DIR)/tests/tkconfig-test
	$(BUILD_DIR)/tests/tkconfig-test
