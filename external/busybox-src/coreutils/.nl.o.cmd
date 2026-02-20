cmd_coreutils/nl.o := /home/lily/vibeos/external/busybox-src/.zigcc-musl-wrapper.sh -Wp,-MD,coreutils/.nl.o.d  -std=gnu99 -Iinclude -Ilibbb  -include include/autoconf.h -D_GNU_SOURCE -DNDEBUG -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DBB_VER='"1.36.1"' -Wall -Wshadow -Wwrite-strings -Wundef -Wstrict-prototypes -Wunused -Wunused-parameter -Wunused-function -Wunused-value -Wmissing-prototypes -Wmissing-declarations -Wno-format-security -Wdeclaration-after-statement -Wold-style-definition -finline-limit=0 -fno-builtin-strlen -fomit-frame-pointer -ffunction-sections -fdata-sections -funsigned-char -static-libgcc -falign-functions=1 -falign-jumps=1 -falign-labels=1 -falign-loops=1 -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-builtin-printf -Oz -mno-avx -mno-avx2 -mno-avx512f -fno-tree-vectorize   -DKBUILD_BASENAME='"nl"'  -DKBUILD_MODNAME='"nl"' -c -o coreutils/nl.o coreutils/nl.c

deps_coreutils/nl.o := \
  coreutils/nl.c \
    $(wildcard include/config/nl.h) \
    $(wildcard include/config/long/opts.h) \
  include/libbb.h \
    $(wildcard include/config/feature/shadowpasswds.h) \
    $(wildcard include/config/use/bb/shadow.h) \
    $(wildcard include/config/selinux.h) \
    $(wildcard include/config/feature/utmp.h) \
    $(wildcard include/config/locale/support.h) \
    $(wildcard include/config/use/bb/pwd/grp.h) \
    $(wildcard include/config/lfs.h) \
    $(wildcard include/config/feature/buffers/go/on/stack.h) \
    $(wildcard include/config/feature/buffers/go/in/bss.h) \
    $(wildcard include/config/extra/cflags.h) \
    $(wildcard include/config/variable/arch/pagesize.h) \
    $(wildcard include/config/feature/verbose.h) \
    $(wildcard include/config/feature/etc/services.h) \
    $(wildcard include/config/feature/ipv6.h) \
    $(wildcard include/config/feature/seamless/xz.h) \
    $(wildcard include/config/feature/seamless/lzma.h) \
    $(wildcard include/config/feature/seamless/bz2.h) \
    $(wildcard include/config/feature/seamless/gz.h) \
    $(wildcard include/config/feature/seamless/z.h) \
    $(wildcard include/config/float/duration.h) \
    $(wildcard include/config/feature/check/names.h) \
    $(wildcard include/config/feature/prefer/applets.h) \
    $(wildcard include/config/feature/pidfile.h) \
    $(wildcard include/config/feature/syslog.h) \
    $(wildcard include/config/feature/syslog/info.h) \
    $(wildcard include/config/warn/simple/msg.h) \
    $(wildcard include/config/feature/individual.h) \
    $(wildcard include/config/shell/ash.h) \
    $(wildcard include/config/shell/hush.h) \
    $(wildcard include/config/echo.h) \
    $(wildcard include/config/sleep.h) \
    $(wildcard include/config/printf.h) \
    $(wildcard include/config/test.h) \
    $(wildcard include/config/test1.h) \
    $(wildcard include/config/test2.h) \
    $(wildcard include/config/kill.h) \
    $(wildcard include/config/killall.h) \
    $(wildcard include/config/killall5.h) \
    $(wildcard include/config/chown.h) \
    $(wildcard include/config/ls.h) \
    $(wildcard include/config/xxx.h) \
    $(wildcard include/config/route.h) \
    $(wildcard include/config/feature/hwib.h) \
    $(wildcard include/config/desktop.h) \
    $(wildcard include/config/feature/crond/d.h) \
    $(wildcard include/config/feature/setpriv/capabilities.h) \
    $(wildcard include/config/run/init.h) \
    $(wildcard include/config/feature/securetty.h) \
    $(wildcard include/config/pam.h) \
    $(wildcard include/config/use/bb/crypt.h) \
    $(wildcard include/config/feature/adduser/to/group.h) \
    $(wildcard include/config/feature/del/user/from/group.h) \
    $(wildcard include/config/ioctl/hex2str/error.h) \
    $(wildcard include/config/feature/editing.h) \
    $(wildcard include/config/feature/editing/history.h) \
    $(wildcard include/config/feature/tab/completion.h) \
    $(wildcard include/config/feature/username/completion.h) \
    $(wildcard include/config/feature/editing/fancy/prompt.h) \
    $(wildcard include/config/feature/editing/savehistory.h) \
    $(wildcard include/config/feature/editing/vi.h) \
    $(wildcard include/config/feature/editing/save/on/exit.h) \
    $(wildcard include/config/pmap.h) \
    $(wildcard include/config/feature/show/threads.h) \
    $(wildcard include/config/feature/ps/additional/columns.h) \
    $(wildcard include/config/feature/topmem.h) \
    $(wildcard include/config/feature/top/smp/process.h) \
    $(wildcard include/config/pgrep.h) \
    $(wildcard include/config/pkill.h) \
    $(wildcard include/config/pidof.h) \
    $(wildcard include/config/sestatus.h) \
    $(wildcard include/config/unicode/support.h) \
    $(wildcard include/config/feature/mtab/support.h) \
    $(wildcard include/config/feature/clean/up.h) \
    $(wildcard include/config/feature/devfs.h) \
  include/platform.h \
    $(wildcard include/config/werror.h) \
    $(wildcard include/config/big/endian.h) \
    $(wildcard include/config/little/endian.h) \
    $(wildcard include/config/nommu.h) \
  /usr/lib64/zig/0.14.1/lib/include/limits.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/limits.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/features.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/x86_64-linux-musl/bits/alltypes.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/x86_64-linux-musl/bits/limits.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/byteswap.h \
  /usr/lib64/zig/0.14.1/lib/include/stdint.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/stdint.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/x86_64-linux-musl/bits/stdint.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/endian.h \
  /usr/lib64/zig/0.14.1/lib/include/stdbool.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/stdbool.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/unistd.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/x86_64-linux-musl/bits/posix.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/ctype.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/dirent.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/bits/dirent.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/errno.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/bits/errno.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/fcntl.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/bits/fcntl.h \
  /usr/lib64/zig/0.14.1/lib/include/inttypes.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/inttypes.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/netdb.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/netinet/in.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/sys/socket.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/bits/socket.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/setjmp.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/x86_64-linux-musl/bits/setjmp.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/signal.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/x86_64-linux-musl/bits/signal.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/paths.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/stdio.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/stdlib.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/alloca.h \
  /usr/lib64/zig/0.14.1/lib/include/stdarg.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/stdarg.h \
  /usr/lib64/zig/0.14.1/lib/include/__stdarg_header_macro.h \
  /usr/lib64/zig/0.14.1/lib/include/__stdarg___gnuc_va_list.h \
  /usr/lib64/zig/0.14.1/lib/include/__stdarg_va_list.h \
  /usr/lib64/zig/0.14.1/lib/include/__stdarg_va_arg.h \
  /usr/lib64/zig/0.14.1/lib/include/__stdarg___va_copy.h \
  /usr/lib64/zig/0.14.1/lib/include/__stdarg_va_copy.h \
  /usr/lib64/zig/0.14.1/lib/include/stddef.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/stddef.h \
  /usr/lib64/zig/0.14.1/lib/include/__stddef_header_macro.h \
  /usr/lib64/zig/0.14.1/lib/include/__stddef_ptrdiff_t.h \
  /usr/lib64/zig/0.14.1/lib/include/__stddef_size_t.h \
  /usr/lib64/zig/0.14.1/lib/include/__stddef_wchar_t.h \
  /usr/lib64/zig/0.14.1/lib/include/__stddef_null.h \
  /usr/lib64/zig/0.14.1/lib/include/__stddef_offsetof.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/string.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/strings.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/libgen.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/poll.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/bits/poll.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/sys/ioctl.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/bits/ioctl.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/bits/ioctl_fix.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/sys/mman.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/x86_64-linux-musl/bits/mman.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/sys/resource.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/sys/time.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/sys/select.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/bits/resource.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/sys/stat.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/x86_64-linux-musl/bits/stat.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/sys/types.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/sys/sysmacros.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/sys/wait.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/termios.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/bits/termios.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/time.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/sys/param.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/pwd.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/grp.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/mntent.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/sys/statfs.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/sys/statvfs.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/bits/statfs.h \
  /usr/lib64/zig/0.14.1/lib/libc/include/generic-musl/arpa/inet.h \
  include/pwd_.h \
  include/grp_.h \
  include/shadow_.h \
  include/xatonum.h \

coreutils/nl.o: $(deps_coreutils/nl.o)

$(deps_coreutils/nl.o):
