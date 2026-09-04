#include <stdio.h>

/* Exercise the actual feature entry points without executing privileged code. */
#include "../kernel/src/syscall.c"

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "kernel config check failed at line %d: %s\n", __LINE__, #condition); \
        return 1; \
    } \
} while (0)

int main(void) {
    int type = 0;
    uint32_t open_flags = 0, fd_flags = 0;
    int result = parse_inet_socket_type(SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP,
                                        &type, &open_flags, &fd_flags);
#ifdef CONFIG_KERNEL_TCP_SOCKETS
    CHECK(result == 0 && type == SOCK_STREAM && fd_flags == FD_CLOEXEC);
#else
    CHECK(result == -EPROTOTYPE);
#endif
    result = parse_inet_socket_type(SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP,
                                    &type, &open_flags, &fd_flags);
#ifdef CONFIG_KERNEL_UDP_SOCKETS
    CHECK(result == 0 && type == SOCK_DGRAM && (open_flags & O_NONBLOCK));
#else
    CHECK(result == -EPROTOTYPE);
#endif
    result = parse_inet_socket_type(SOCK_RAW, IPPROTO_ICMP, &type, &open_flags, &fd_flags);
#ifdef CONFIG_KERNEL_RAW_ICMP_SOCKETS
    CHECK(result == 0 && type == SOCK_RAW);
#else
    CHECK(result == -EPROTOTYPE);
#endif
#ifndef CONFIG_KERNEL_INET
    CHECK(sys_socket(AF_INET, SOCK_STREAM, 0) == -EAFNOSUPPORT);
#endif
#ifndef CONFIG_KERNEL_UNIX_SOCKETS
    CHECK(sys_socket(AF_UNIX, SOCK_STREAM, 0) == -EAFNOSUPPORT);
    CHECK(sys_socketpair(AF_UNIX, SOCK_STREAM, 0, NULL) == -EAFNOSUPPORT);
#endif
#ifndef CONFIG_KERNEL_PIPES
    CHECK(sys_pipe2(NULL, 0) == -ENOSYS);
#endif
#ifndef CONFIG_KERNEL_SYMLINK_CREATE
    CHECK(sys_symlinkat(NULL, AT_FDCWD, NULL) == -ENOSYS);
#endif
#ifndef CONFIG_KERNEL_HARDLINK_CREATE
    CHECK(sys_linkat(AT_FDCWD, NULL, AT_FDCWD, NULL, 0) == -ENOSYS);
#endif
#ifndef CONFIG_KERNEL_REBOOT
    CHECK(sys_reboot(0, 0, 0) == -ENOSYS);
#endif
#ifndef CONFIG_KERNEL_SETHOSTNAME
    CHECK(sys_sethostname(NULL, 0) == -ENOSYS);
#endif
#ifdef CONFIG_KERNEL_PTYS
    CHECK(device_path_enabled("/dev/ptmx") && is_ptmx_path("/dev/ptmx"));
    CHECK(pty_slave_for_path("/dev/pts/0") == 0);
#else
    CHECK(!device_path_enabled("/dev/ptmx") && !is_ptmx_path("/dev/ptmx"));
    CHECK(!device_path_enabled("/dev/pts/0") && pty_slave_for_path("/dev/pts/0") == -1);
#endif
#ifdef CONFIG_KERNEL_FBDEV
    CHECK(device_path_enabled("/dev/fb0") && is_fb_path("/dev/fb0"));
#else
    CHECK(!device_path_enabled("/dev/fb0") && !is_fb_path("/dev/fb0"));
#endif
#if defined(CONFIG_KERNEL_INPUT_EVENTS) && defined(CONFIG_KERNEL_PS2_KEYBOARD)
    CHECK(input_device_for_path("/dev/input/event1") == INPUT_EVENT_KEYBOARD);
#else
    CHECK(!device_path_enabled("/dev/input/event1"));
    CHECK(input_device_for_path("/dev/input/event1") == -1);
#endif
#if defined(CONFIG_KERNEL_INPUT_EVENTS) && defined(CONFIG_KERNEL_PS2_MOUSE)
    CHECK(input_device_for_path("/dev/input/event0") == INPUT_EVENT_POINTER);
#else
    CHECK(!device_path_enabled("/dev/input/event0"));
    CHECK(input_device_for_path("/dev/input/event0") == -1);
#endif
    CHECK(device_path_enabled("/dev/null"));
    CHECK(device_path_enabled("/dev/tty"));
    puts("kernel config feature checks passed");
    return 0;
}
