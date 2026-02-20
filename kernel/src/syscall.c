#include "syscall.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common.h"
#include "console.h"
#include "input.h"
#include "initramfs.h"
#include "io.h"
#include "string.h"
#include "userland.h"

#define IA32_FS_BASE 0xC0000100u
#define IA32_STAR 0xC0000081u
#define IA32_LSTAR 0xC0000082u
#define IA32_FMASK 0xC0000084u
#define IA32_EFER 0xC0000080u

#define EFER_SCE (1ull << 0)

#define AT_FDCWD (-100)

#define O_RDONLY 0u
#define O_WRONLY 1u
#define O_RDWR 2u
#define O_CREAT 0x40u
#define O_DIRECTORY 0x10000u

#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

#define S_IFMT 0170000u
#define S_IFIFO 0010000u
#define S_IFCHR 0020000u
#define S_IFDIR 0040000u
#define S_IFREG 0100000u
#define S_IFLNK 0120000u

#define DT_UNKNOWN 0
#define DT_FIFO 1
#define DT_CHR 2
#define DT_DIR 4
#define DT_REG 8
#define DT_LNK 10

#define ARCH_SET_FS 0x1002u
#define ARCH_GET_FS 0x1003u

#define TCGETS 0x5401u
#define TIOCGWINSZ 0x5413u

#define MAX_FDS 64
#define MAX_CHILDREN 256
#define USER_STACK_TOP 0x08000000ull
#define USER_BRK_BASE 0x14000000ull
#define USER_MMAP_BASE 0x18000000ull
#define USER_MMAP_LIMIT 0x1F000000ull

#define MAP_FIXED 0x10u
#define MAP_FIXED_NOREPLACE 0x100000u

#define ENOSYS 38
#define ENOENT 2
#define EINTR 4
#define ECHILD 10
#define EAGAIN 11
#define EBADF 9
#define EFAULT 14
#define EINVAL 22
#define ENOTTY 25
#define ENOTDIR 20
#define EISDIR 21
#define ENOTSUP 95
#define ESPIPE 29
#define ENOMEM 12
#define EEXIST 17

#define IRET_SLOT_RIP 15u
#define IRET_SLOT_CS 16u
#define IRET_SLOT_RFLAGS 17u
#define IRET_SLOT_RSP 18u
#define IRET_SLOT_SS 19u

#define CLONE_SIGNAL_MASK 0xFFull
#define CLONE_VM 0x00000100ull
#define CLONE_VFORK 0x00004000ull
#define CLONE_SETTLS 0x00080000ull
#define CLONE_CHILD_CLEARTID 0x00200000ull
#define CLONE_CHILD_SETTID 0x01000000ull
#define SIGCHLD 17u
#define SIGINT 2u
#define SIGTSTP 20u

#define WAIT_NOHANG 1u

#define FORK_IMAGE_SNAPSHOT_MAX (16u * 1024u * 1024u)
#define FORK_STACK_SNAPSHOT_MAX (8u * 1024u * 1024u)
#define FORK_BRK_SNAPSHOT_MAX (8u * 1024u * 1024u)
#define FORK_MMAP_SNAPSHOT_MAX (16u * 1024u * 1024u)

#define MAX_PIPES 64
#define PIPE_CAPACITY 65536

#define EXEC_MAX_ARGS 64
#define EXEC_MAX_ENVS 64
#define EXEC_STR_MAX 256
#define EXEC_MAX_SYMLINKS 8

#define ELF_MAGIC 0x464C457Fu
#define ET_EXEC 2u
#define PT_LOAD 1u
#define USER_ELF_LIMIT 0x3F000000ull

struct linux_iovec {
    uint64_t base;
    uint64_t len;
};

struct linux_winsize {
    uint16_t ws_row;
    uint16_t ws_col;
    uint16_t ws_xpixel;
    uint16_t ws_ypixel;
};

struct linux_utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

struct linux_timespec {
    int64_t tv_sec;
    int64_t tv_nsec;
};

struct linux_stat {
    uint64_t st_dev;
    uint64_t st_ino;
    uint64_t st_nlink;
    uint32_t st_mode;
    uint32_t st_uid;
    uint32_t st_gid;
    uint32_t __pad0;
    uint64_t st_rdev;
    int64_t st_size;
    int64_t st_blksize;
    int64_t st_blocks;
    int64_t st_atime;
    uint64_t st_atime_nsec;
    int64_t st_mtime;
    uint64_t st_mtime_nsec;
    int64_t st_ctime;
    uint64_t st_ctime_nsec;
    int64_t __unused[3];
};

struct linux_statx_timestamp {
    int64_t tv_sec;
    uint32_t tv_nsec;
    int32_t __reserved;
};

struct linux_statx {
    uint32_t stx_mask;
    uint32_t stx_blksize;
    uint64_t stx_attributes;
    uint32_t stx_nlink;
    uint32_t stx_uid;
    uint32_t stx_gid;
    uint16_t stx_mode;
    uint16_t __spare0[1];
    uint64_t stx_ino;
    uint64_t stx_size;
    uint64_t stx_blocks;
    uint64_t stx_attributes_mask;
    struct linux_statx_timestamp stx_atime;
    struct linux_statx_timestamp stx_btime;
    struct linux_statx_timestamp stx_ctime;
    struct linux_statx_timestamp stx_mtime;
    uint32_t stx_rdev_major;
    uint32_t stx_rdev_minor;
    uint32_t stx_dev_major;
    uint32_t stx_dev_minor;
    uint64_t stx_mnt_id;
    uint64_t __spare2[13];
};

struct linux_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    uint16_t d_reclen;
    uint8_t d_type;
    char d_name[];
};

struct elf64_ehdr {
    uint8_t e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} __attribute__((packed));

struct elf64_phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} __attribute__((packed));

enum fd_kind {
    FD_FREE = 0,
    FD_TTY,
    FD_FILE,
    FD_DIR,
    FD_NULL,
    FD_PIPE_R,
    FD_PIPE_W,
};

struct fd_state {
    enum fd_kind kind;
    uint32_t flags;
    size_t offset;
    int pipe_id;
    struct initramfs_entry entry;
    char path[128];
};

struct pipe_state {
    bool used;
    size_t read_off;
    size_t size;
    uint8_t data[PIPE_CAPACITY];
};

static struct fd_state g_fds[MAX_FDS];
static char g_cwd[128] = "/";
static uint64_t g_brk_current = USER_BRK_BASE;
static uint64_t g_mmap_next = USER_MMAP_BASE;
static uint64_t g_rng_state = 0x123456789abcdef0ull;
static char g_dirent_names[MAX_CHILDREN][64];
static uint8_t g_dirent_types[MAX_CHILDREN];
static char g_exec_argv_scratch[EXEC_MAX_ARGS][EXEC_STR_MAX];
static char g_exec_env_scratch[EXEC_MAX_ENVS][EXEC_STR_MAX];
static uint64_t g_exec_argv_ptrs[EXEC_MAX_ARGS];
static uint64_t g_exec_env_ptrs[EXEC_MAX_ENVS];
static uint64_t g_fake_time_ns;
static int g_current_pid = 1;
static int g_current_ppid = 0;
static int g_next_pid = 2;
static int g_pending_child_pid;
static int g_saved_parent_pid = 1;
static int g_saved_parent_ppid = 0;
static bool g_parent_pending;
static bool g_child_has_cleartid;
static uint64_t g_child_cleartid_ptr;
static bool g_wait_status_valid;
static int g_wait_status_pid;
static int g_wait_status_code;
static int g_pending_keyboard_signal;

static struct fd_state g_parent_fds[MAX_FDS];
static char g_parent_cwd[128];
static uint64_t g_parent_brk_current;
static uint64_t g_parent_mmap_next;
static uint64_t g_parent_fs_base;
static uint64_t g_parent_tid_address;
static struct syscall_frame g_parent_frame;
static uint64_t g_parent_iret[5];

static uint64_t g_snap_image_base;
static size_t g_snap_image_len;
static uint8_t g_snap_image[FORK_IMAGE_SNAPSHOT_MAX];

static uint64_t g_snap_stack_base;
static size_t g_snap_stack_len;
static uint8_t g_snap_stack[FORK_STACK_SNAPSHOT_MAX];

static uint64_t g_snap_brk_base;
static size_t g_snap_brk_len;
static uint8_t g_snap_brk[FORK_BRK_SNAPSHOT_MAX];

static uint64_t g_snap_mmap_base;
static size_t g_snap_mmap_len;
static uint8_t g_snap_mmap[FORK_MMAP_SNAPSHOT_MAX];
static struct pipe_state g_pipes[MAX_PIPES];
static uint64_t g_tid_address;

extern void leave_user_mode(uint64_t code) __attribute__((noreturn));
extern void syscall_entry(void);

static int normalize_path(const char* input, char* out, size_t out_len);
static int join_path(const char* base, const char* leaf, char* out, size_t out_len);

static int err(int code) {
    return -code;
}

static bool is_keyboard_signal(int signal) {
    return signal == (int)SIGINT || signal == (int)SIGTSTP;
}

static void queue_keyboard_signal(int signal) {
    if (!is_keyboard_signal(signal) || g_pending_keyboard_signal != 0) {
        return;
    }
    g_pending_keyboard_signal = signal;
}

static int take_keyboard_signal(void) {
    int signal = g_pending_keyboard_signal;
    g_pending_keyboard_signal = 0;
    return signal;
}

static uint64_t xorshift64(void) {
    uint64_t x = g_rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    g_rng_state = x;
    return x;
}

static uint64_t read_fs_base_current(void) {
    if ((read_cr4() & (1ull << 16)) != 0ull) {
        return read_fs_base_inst();
    }
    return rdmsr(IA32_FS_BASE);
}

static void write_fs_base_current(uint64_t base) {
    if ((read_cr4() & (1ull << 16)) != 0ull) {
        write_fs_base_inst(base);
    }
    wrmsr(IA32_FS_BASE, base);
}

static int snapshot_range(uint64_t base, size_t len, uint8_t* dst, size_t dst_cap) {
    if (len == 0) {
        return 0;
    }
    if (len > dst_cap) {
        return err(ENOMEM);
    }
    if (base < 0x1000ull || base + len < base || base + len >= USER_MMAP_LIMIT) {
        return err(EINVAL);
    }
    memcpy(dst, (const void*)(uintptr_t)base, len);
    return 0;
}

static void restore_range(uint64_t base, size_t len, const uint8_t* src) {
    if (len == 0) {
        return;
    }
    memcpy((void*)(uintptr_t)base, src, len);
}

static int snapshot_parent_memory(struct syscall_frame* frame) {
    uint64_t image_start = 0;
    uint64_t image_end = 0;
    userland_get_image_span(&image_start, &image_end);

    g_snap_image_base = 0;
    g_snap_image_len = 0;
    g_snap_stack_base = 0;
    g_snap_stack_len = 0;
    g_snap_brk_base = USER_BRK_BASE;
    g_snap_brk_len = 0;
    g_snap_mmap_base = USER_MMAP_BASE;
    g_snap_mmap_len = 0;

    if (image_end > image_start) {
        g_snap_image_base = image_start;
        g_snap_image_len = (size_t)(image_end - image_start);
        int sr = snapshot_range(g_snap_image_base, g_snap_image_len, g_snap_image, sizeof(g_snap_image));
        if (sr != 0) {
            return sr;
        }
    }

    uint64_t* raw = (uint64_t*)(void*)frame;
    uint64_t user_rsp = raw[IRET_SLOT_RSP];
    if (user_rsp == 0 || user_rsp > USER_STACK_TOP) {
        return err(EINVAL);
    }

    g_snap_stack_base = user_rsp & ~0x0Full;
    if (g_snap_stack_base > USER_STACK_TOP) {
        return err(EINVAL);
    }
    g_snap_stack_len = (size_t)(USER_STACK_TOP - g_snap_stack_base);
    int sr = snapshot_range(g_snap_stack_base, g_snap_stack_len, g_snap_stack, sizeof(g_snap_stack));
    if (sr != 0) {
        return sr;
    }

    if (g_brk_current > USER_BRK_BASE) {
        g_snap_brk_len = (size_t)(g_brk_current - USER_BRK_BASE);
        sr = snapshot_range(g_snap_brk_base, g_snap_brk_len, g_snap_brk, sizeof(g_snap_brk));
        if (sr != 0) {
            return sr;
        }
    }

    if (g_mmap_next > USER_MMAP_BASE) {
        g_snap_mmap_len = (size_t)(g_mmap_next - USER_MMAP_BASE);
        sr = snapshot_range(g_snap_mmap_base, g_snap_mmap_len, g_snap_mmap, sizeof(g_snap_mmap));
        if (sr != 0) {
            return sr;
        }
    }

    return 0;
}

static void restore_parent_runtime_state(void) {
    restore_range(g_snap_image_base, g_snap_image_len, g_snap_image);
    restore_range(g_snap_stack_base, g_snap_stack_len, g_snap_stack);
    restore_range(g_snap_brk_base, g_snap_brk_len, g_snap_brk);
    restore_range(g_snap_mmap_base, g_snap_mmap_len, g_snap_mmap);

    memcpy(g_fds, g_parent_fds, sizeof(g_fds));
    memcpy(g_cwd, g_parent_cwd, sizeof(g_cwd));
    g_brk_current = g_parent_brk_current;
    g_mmap_next = g_parent_mmap_next;
    g_tid_address = g_parent_tid_address;
    write_fs_base_current(g_parent_fs_base);

    g_current_pid = g_saved_parent_pid;
    g_current_ppid = g_saved_parent_ppid;
    g_parent_pending = false;
    g_pending_child_pid = 0;
    g_child_has_cleartid = false;
    g_child_cleartid_ptr = 0;
}

static uint64_t resume_parent_after_child_exit(struct syscall_frame* frame, uint64_t code) {
    if (g_child_has_cleartid && g_child_cleartid_ptr != 0) {
        *(uint32_t*)(uintptr_t)g_child_cleartid_ptr = 0;
    }

    g_wait_status_pid = g_pending_child_pid;
    g_wait_status_code = ((int)(code & 0xFFu)) << 8;
    g_wait_status_valid = true;

    restore_parent_runtime_state();

    *frame = g_parent_frame;
    uint64_t* raw = (uint64_t*)(void*)frame;
    raw[IRET_SLOT_RIP] = g_parent_iret[0];
    raw[IRET_SLOT_CS] = g_parent_iret[1];
    raw[IRET_SLOT_RFLAGS] = g_parent_iret[2];
    raw[IRET_SLOT_RSP] = g_parent_iret[3];
    raw[IRET_SLOT_SS] = g_parent_iret[4];
    return g_parent_frame.rax;
}

static uint64_t resume_parent_after_child_signal(struct syscall_frame* frame, int signal) {
    if (g_child_has_cleartid && g_child_cleartid_ptr != 0) {
        *(uint32_t*)(uintptr_t)g_child_cleartid_ptr = 0;
    }

    g_wait_status_pid = g_pending_child_pid;
    g_wait_status_code = signal & 0x7F;
    g_wait_status_valid = true;

    restore_parent_runtime_state();

    *frame = g_parent_frame;
    uint64_t* raw = (uint64_t*)(void*)frame;
    raw[IRET_SLOT_RIP] = g_parent_iret[0];
    raw[IRET_SLOT_CS] = g_parent_iret[1];
    raw[IRET_SLOT_RFLAGS] = g_parent_iret[2];
    raw[IRET_SLOT_RSP] = g_parent_iret[3];
    raw[IRET_SLOT_SS] = g_parent_iret[4];
    return g_parent_frame.rax;
}

static bool is_null_path(const char* path) {
    return strcmp(path, "/dev/null") == 0;
}

static bool is_proc_self_exe_path(const char* path) {
    return strcmp(path, "/proc/self/exe") == 0;
}

static void dirname_of(const char* path, char* out, size_t out_len) {
    if (out_len < 2) {
        return;
    }

    size_t len = strlen(path);
    while (len > 1 && path[len - 1] == '/') {
        --len;
    }

    size_t slash = len;
    while (slash > 0 && path[slash - 1] != '/') {
        --slash;
    }

    if (slash == 0) {
        strcpy(out, "/");
        return;
    }
    if (slash == 1) {
        strcpy(out, "/");
        return;
    }

    if (slash >= out_len) {
        slash = out_len - 1;
    }
    memcpy(out, path, slash);
    out[slash] = '\0';
}

static int resolve_symlinks(const char* abs_in, char* abs_out, size_t out_len, bool follow_final) {
    char current[128];
    strncpy(current, abs_in, sizeof(current));
    current[sizeof(current) - 1] = '\0';

    for (int depth = 0; depth < EXEC_MAX_SYMLINKS; ++depth) {
        if (is_proc_self_exe_path(current)) {
            strncpy(abs_out, "/bin/busybox", out_len);
            abs_out[out_len - 1] = '\0';
            return 0;
        }

        struct initramfs_entry e;
        if (initramfs_find(current, &e) != 0) {
            strncpy(abs_out, current, out_len);
            abs_out[out_len - 1] = '\0';
            return 0;
        }

        bool is_link = ((e.mode & S_IFMT) == S_IFLNK);
        if (!is_link || !follow_final) {
            strncpy(abs_out, current, out_len);
            abs_out[out_len - 1] = '\0';
            return 0;
        }

        char target_raw[128];
        size_t n = e.size;
        if (n >= sizeof(target_raw)) {
            n = sizeof(target_raw) - 1;
        }
        memcpy(target_raw, e.data, n);
        target_raw[n] = '\0';

        char next[256];
        if (target_raw[0] == '/') {
            int nr = normalize_path(target_raw, next, sizeof(next));
            if (nr != 0) {
                return nr;
            }
        } else {
            char dir[128];
            dirname_of(current, dir, sizeof(dir));
            int jr = join_path(dir, target_raw, next, sizeof(next));
            if (jr != 0) {
                return jr;
            }
            char normalized[128];
            int nr = normalize_path(next, normalized, sizeof(normalized));
            if (nr != 0) {
                return nr;
            }
            strncpy(next, normalized, sizeof(next));
            next[sizeof(next) - 1] = '\0';
        }

        strncpy(current, next, sizeof(current));
        current[sizeof(current) - 1] = '\0';
    }

    return err(EINVAL);
}

static bool pipe_is_referenced_in_fd_table(const struct fd_state* fds, int pipe_id) {
    for (int fd = 0; fd < MAX_FDS; ++fd) {
        if ((fds[fd].kind == FD_PIPE_R || fds[fd].kind == FD_PIPE_W) && fds[fd].pipe_id == pipe_id) {
            return true;
        }
    }
    return false;
}

static bool pipe_is_referenced(int pipe_id) {
    if (pipe_is_referenced_in_fd_table(g_fds, pipe_id)) {
        return true;
    }
    if (g_parent_pending && pipe_is_referenced_in_fd_table(g_parent_fds, pipe_id)) {
        return true;
    }
    return false;
}

static bool pipe_has_writer(int pipe_id) {
    for (int fd = 0; fd < MAX_FDS; ++fd) {
        if (g_fds[fd].kind == FD_PIPE_W && g_fds[fd].pipe_id == pipe_id) {
            return true;
        }
    }
    return false;
}

static int alloc_pipe_slot(void) {
    for (int i = 0; i < MAX_PIPES; ++i) {
        if (!g_pipes[i].used) {
            memset(&g_pipes[i], 0, sizeof(g_pipes[i]));
            g_pipes[i].used = true;
            return i;
        }
    }
    return err(ENOMEM);
}

static bool is_special_dir(const char* path) {
    return (strcmp(path, "/") == 0) || (strcmp(path, "/dev") == 0) || (strcmp(path, "/proc") == 0) ||
           (strcmp(path, "/sys") == 0) || (strcmp(path, "/tmp") == 0) || (strcmp(path, "/bin") == 0) ||
           (strcmp(path, "/usr") == 0) || (strcmp(path, "/usr/bin") == 0) || (strcmp(path, "/etc") == 0) ||
           (strcmp(path, "/var") == 0) || (strcmp(path, "/home") == 0);
}

static bool is_tty_path(const char* path) {
    return (strcmp(path, "/dev/tty") == 0) || (strcmp(path, "/dev/console") == 0);
}

static int normalize_path(const char* input, char* out, size_t out_len) {
    if (out_len < 2) {
        return err(EINVAL);
    }

    char components[32][64];
    size_t count = 0;

    size_t i = 0;
    while (input[i] != '\0') {
        while (input[i] == '/') {
            ++i;
        }
        if (input[i] == '\0') {
            break;
        }

        char segment[64];
        size_t seg_len = 0;
        while (input[i] != '\0' && input[i] != '/' && seg_len + 1 < sizeof(segment)) {
            segment[seg_len++] = input[i++];
        }
        segment[seg_len] = '\0';

        while (input[i] != '\0' && input[i] != '/') {
            ++i;
        }

        if (strcmp(segment, ".") == 0 || seg_len == 0) {
            continue;
        }
        if (strcmp(segment, "..") == 0) {
            if (count > 0) {
                --count;
            }
            continue;
        }

        if (count >= ARRAY_LEN(components)) {
            return err(ENOMEM);
        }

        strncpy(components[count], segment, sizeof(components[count]));
        components[count][sizeof(components[count]) - 1] = '\0';
        ++count;
    }

    size_t pos = 0;
    out[pos++] = '/';

    for (size_t c = 0; c < count; ++c) {
        size_t len = strlen(components[c]);
        if (pos + len + 1 >= out_len) {
            return err(ENOMEM);
        }
        memcpy(&out[pos], components[c], len);
        pos += len;
        if (c + 1 < count) {
            out[pos++] = '/';
        }
    }

    out[pos] = '\0';
    return 0;
}

static int join_path(const char* base, const char* leaf, char* out, size_t out_len) {
    size_t pos = 0;
    if (base[0] == '\0') {
        return err(EINVAL);
    }

    if (strcmp(base, "/") == 0) {
        if (out_len < 2) {
            return err(ENOMEM);
        }
        out[pos++] = '/';
    } else {
        size_t base_len = strlen(base);
        if (base_len + 1 >= out_len) {
            return err(ENOMEM);
        }
        memcpy(out, base, base_len);
        pos = base_len;
        if (out[pos - 1] != '/') {
            out[pos++] = '/';
        }
    }

    for (size_t i = 0; leaf[i] != '\0'; ++i) {
        if (pos + 1 >= out_len) {
            return err(ENOMEM);
        }
        out[pos++] = leaf[i];
    }

    out[pos] = '\0';
    return 0;
}

static int make_absolute_path(int dirfd, const char* path, char* out, size_t out_len) {
    if (path == NULL) {
        return err(EINVAL);
    }

    if (path[0] == '/') {
        return normalize_path(path, out, out_len);
    }

    char base[128];
    if (dirfd == AT_FDCWD) {
        strncpy(base, g_cwd, sizeof(base));
        base[sizeof(base) - 1] = '\0';
    } else {
        if (dirfd < 0 || dirfd >= MAX_FDS || g_fds[dirfd].kind == FD_FREE) {
            return err(EBADF);
        }
        if (g_fds[dirfd].kind != FD_DIR) {
            return err(ENOTDIR);
        }
        strncpy(base, g_fds[dirfd].path, sizeof(base));
        base[sizeof(base) - 1] = '\0';
    }

    char joined[256];
    int jr = join_path(base, path, joined, sizeof(joined));
    if (jr != 0) {
        return jr;
    }

    return normalize_path(joined, out, out_len);
}

static bool path_has_child(const char* dir) {
    size_t dir_len = strlen(dir);
    for (size_t i = 0; i < initramfs_entry_count(); ++i) {
        const struct initramfs_entry* e = initramfs_entry_at(i);
        if (e == NULL) {
            continue;
        }
        if (strcmp(dir, "/") == 0) {
            if (strcmp(e->path, "/") != 0) {
                return true;
            }
            continue;
        }
        if (strncmp(e->path, dir, dir_len) == 0 && e->path[dir_len] == '/' && e->path[dir_len + 1] != '\0') {
            return true;
        }
    }
    return false;
}

static int path_mode_size(const char* path, uint32_t* mode_out, size_t* size_out, struct initramfs_entry* entry_out) {
    struct initramfs_entry e;

    if (is_tty_path(path)) {
        if (mode_out != NULL) {
            *mode_out = S_IFCHR | 0666u;
        }
        if (size_out != NULL) {
            *size_out = 0;
        }
        if (entry_out != NULL) {
            memset(entry_out, 0, sizeof(*entry_out));
            strncpy(entry_out->path, path, sizeof(entry_out->path));
            entry_out->mode = S_IFCHR | 0666u;
        }
        return 0;
    }

    if (is_null_path(path)) {
        if (mode_out != NULL) {
            *mode_out = S_IFCHR | 0666u;
        }
        if (size_out != NULL) {
            *size_out = 0;
        }
        if (entry_out != NULL) {
            memset(entry_out, 0, sizeof(*entry_out));
            strncpy(entry_out->path, path, sizeof(entry_out->path));
            entry_out->mode = S_IFCHR | 0666u;
        }
        return 0;
    }

    if (is_proc_self_exe_path(path)) {
        const char* target = "/bin/busybox";
        if (mode_out != NULL) {
            *mode_out = S_IFLNK | 0777u;
        }
        if (size_out != NULL) {
            *size_out = strlen(target);
        }
        if (entry_out != NULL) {
            memset(entry_out, 0, sizeof(*entry_out));
            strncpy(entry_out->path, path, sizeof(entry_out->path));
            entry_out->mode = S_IFLNK | 0777u;
            entry_out->data = (const uint8_t*)target;
            entry_out->size = strlen(target);
        }
        return 0;
    }

    if (initramfs_find(path, &e) == 0) {
        if (mode_out != NULL) {
            *mode_out = e.mode;
        }
        if (size_out != NULL) {
            *size_out = e.size;
        }
        if (entry_out != NULL) {
            *entry_out = e;
        }
        return 0;
    }

    if (is_special_dir(path) || path_has_child(path)) {
        if (mode_out != NULL) {
            *mode_out = S_IFDIR | 0755u;
        }
        if (size_out != NULL) {
            *size_out = 0;
        }
        if (entry_out != NULL) {
            memset(entry_out, 0, sizeof(*entry_out));
            strncpy(entry_out->path, path, sizeof(entry_out->path));
            entry_out->mode = S_IFDIR | 0755u;
        }
        return 0;
    }

    return err(ENOENT);
}

static int alloc_fd(void) {
    for (int fd = 0; fd < MAX_FDS; ++fd) {
        if (g_fds[fd].kind == FD_FREE) {
            return fd;
        }
    }
    return err(ENOMEM);
}

static int alloc_fd_from(int min_fd) {
    if (min_fd < 0) {
        min_fd = 0;
    }
    for (int fd = min_fd; fd < MAX_FDS; ++fd) {
        if (g_fds[fd].kind == FD_FREE) {
            return fd;
        }
    }
    return err(ENOMEM);
}

static bool path_immediate_child(const char* dir, const char* full, char* child_out, size_t child_out_len) {
    if (strcmp(full, "/") == 0) {
        return false;
    }

    const char* rest = NULL;
    size_t dir_len = strlen(dir);
    if (strcmp(dir, "/") == 0) {
        if (full[0] != '/' || full[1] == '\0') {
            return false;
        }
        rest = full + 1;
    } else {
        if (strncmp(full, dir, dir_len) != 0 || full[dir_len] != '/') {
            return false;
        }
        rest = full + dir_len + 1;
    }

    if (*rest == '\0') {
        return false;
    }

    size_t i = 0;
    while (rest[i] != '\0' && rest[i] != '/' && i + 1 < child_out_len) {
        child_out[i] = rest[i];
        ++i;
    }
    child_out[i] = '\0';

    return i > 0;
}

static int child_index_of(char names[MAX_CHILDREN][64], size_t count, const char* name) {
    for (size_t i = 0; i < count; ++i) {
        if (strcmp(names[i], name) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static uint8_t mode_to_dtype(uint32_t mode) {
    switch (mode & S_IFMT) {
        case S_IFREG:
            return DT_REG;
        case S_IFDIR:
            return DT_DIR;
        case S_IFCHR:
            return DT_CHR;
        case S_IFIFO:
            return DT_FIFO;
        case S_IFLNK:
            return DT_LNK;
        default:
            return DT_UNKNOWN;
    }
}

static size_t collect_children(const char* dir, char names[MAX_CHILDREN][64], uint8_t types[MAX_CHILDREN]) {
    size_t count = 0;

    const char* synthetic[] = {".", ".."};
    for (size_t i = 0; i < ARRAY_LEN(synthetic); ++i) {
        strncpy(names[count], synthetic[i], 64);
        names[count][63] = '\0';
        types[count] = DT_DIR;
        ++count;
    }

    for (size_t i = 0; i < initramfs_entry_count(); ++i) {
        const struct initramfs_entry* e = initramfs_entry_at(i);
        if (e == NULL) {
            continue;
        }

        char child[64];
        if (!path_immediate_child(dir, e->path, child, sizeof(child))) {
            continue;
        }

        if (child_index_of(names, count, child) >= 0) {
            continue;
        }

        if (count >= MAX_CHILDREN) {
            break;
        }

        strncpy(names[count], child, 64);
        names[count][63] = '\0';

        char child_full[128];
        if (join_path(dir, child, child_full, sizeof(child_full)) != 0) {
            continue;
        }

        uint32_t mode = 0;
        if (path_mode_size(child_full, &mode, NULL, NULL) != 0) {
            mode = S_IFREG | 0644u;
        }
        types[count] = mode_to_dtype(mode);
        ++count;
    }

    if (strcmp(dir, "/dev") == 0) {
        const char* dev_nodes[] = {"tty", "console", "null"};
        for (size_t i = 0; i < ARRAY_LEN(dev_nodes) && count < MAX_CHILDREN; ++i) {
            if (child_index_of(names, count, dev_nodes[i]) >= 0) {
                continue;
            }
            strncpy(names[count], dev_nodes[i], 64);
            names[count][63] = '\0';
            types[count] = DT_CHR;
            ++count;
        }
    }

    return count;
}

static int copy_user_string(const char* user, char* out, size_t out_len) {
    if (user == NULL || out_len == 0) {
        return err(EINVAL);
    }

    for (size_t i = 0; i < out_len; ++i) {
        char c = user[i];
        out[i] = c;
        if (c == '\0') {
            return 0;
        }
    }

    out[out_len - 1] = '\0';
    return err(ENOMEM);
}

static void fill_stat(struct linux_stat* st, uint32_t mode, size_t size) {
    memset(st, 0, sizeof(*st));
    st->st_mode = mode;
    st->st_size = (int64_t)size;
    st->st_nlink = 1;
    st->st_blksize = 4096;
    st->st_blocks = (int64_t)((size + 511u) / 512u);
    st->st_ino = 1;
    st->st_dev = 1;
    st->st_rdev = 1;
}

static int sys_openat(int dirfd, const char* path_user, uint32_t flags) {
    char path_input[128];
    if (copy_user_string(path_user, path_input, sizeof(path_input)) != 0) {
        return err(EINVAL);
    }

    char path_abs[128];
    int r = make_absolute_path(dirfd, path_input, path_abs, sizeof(path_abs));
    if (r != 0) {
        return r;
    }

    char path[128];
    r = resolve_symlinks(path_abs, path, sizeof(path), true);
    if (r != 0) {
        return r;
    }

    if (is_tty_path(path)) {
        int fd = alloc_fd();
        if (fd < 0) {
            return fd;
        }
        g_fds[fd].kind = FD_TTY;
        g_fds[fd].flags = flags;
        g_fds[fd].offset = 0;
        g_fds[fd].pipe_id = -1;
        strncpy(g_fds[fd].path, path, sizeof(g_fds[fd].path));
        return fd;
    }

    if (is_null_path(path)) {
        int fd = alloc_fd();
        if (fd < 0) {
            return fd;
        }
        g_fds[fd].kind = FD_NULL;
        g_fds[fd].flags = flags;
        g_fds[fd].offset = 0;
        g_fds[fd].pipe_id = -1;
        strncpy(g_fds[fd].path, path, sizeof(g_fds[fd].path));
        return fd;
    }

    struct initramfs_entry e;
    uint32_t mode = 0;
    size_t size = 0;
    r = path_mode_size(path, &mode, &size, &e);
    if (r != 0) {
        if ((flags & O_CREAT) != 0u && is_null_path(path_abs)) {
            int fd = alloc_fd();
            if (fd < 0) {
                return fd;
            }
            g_fds[fd].kind = FD_NULL;
            g_fds[fd].flags = flags;
            g_fds[fd].offset = 0;
            g_fds[fd].pipe_id = -1;
            strncpy(g_fds[fd].path, "/dev/null", sizeof(g_fds[fd].path));
            return fd;
        }
        return r;
    }

    if (((flags & O_DIRECTORY) != 0u) && ((mode & S_IFMT) != S_IFDIR)) {
        return err(ENOTDIR);
    }

    int fd = alloc_fd();
    if (fd < 0) {
        return fd;
    }

    g_fds[fd].flags = flags;
    g_fds[fd].offset = 0;
    g_fds[fd].pipe_id = -1;
    strncpy(g_fds[fd].path, path, sizeof(g_fds[fd].path));
    g_fds[fd].entry = e;

    if ((mode & S_IFMT) == S_IFDIR) {
        g_fds[fd].kind = FD_DIR;
    } else {
        g_fds[fd].kind = FD_FILE;
    }

    (void)size;
    return fd;
}

static int sys_close(int fd) {
    if (fd < 0 || fd >= MAX_FDS || g_fds[fd].kind == FD_FREE) {
        return err(EBADF);
    }

    enum fd_kind kind = g_fds[fd].kind;
    int pipe_id = g_fds[fd].pipe_id;
    memset(&g_fds[fd], 0, sizeof(g_fds[fd]));
    g_fds[fd].pipe_id = -1;

    if ((kind == FD_PIPE_R || kind == FD_PIPE_W) && pipe_id >= 0 && pipe_id < MAX_PIPES && g_pipes[pipe_id].used &&
        !pipe_is_referenced(pipe_id)) {
        memset(&g_pipes[pipe_id], 0, sizeof(g_pipes[pipe_id]));
    }
    return 0;
}

static int sys_read(int fd, void* buf, size_t count) {
    if (count == 0) {
        return 0;
    }
    if (fd < 0 || fd >= MAX_FDS || g_fds[fd].kind == FD_FREE) {
        return err(EBADF);
    }

    if (g_fds[fd].kind == FD_TTY) {
        if (g_pending_keyboard_signal != 0) {
            return err(EINTR);
        }

        char* out = (char*)buf;
        size_t written = 0;
        while (written < count) {
            int c = (written == 0) ? input_read_char_blocking() : input_poll_char();
            queue_keyboard_signal(input_poll_signal());
            if (c < 0) {
                if (written == 0 && g_pending_keyboard_signal != 0) {
                    return err(EINTR);
                }
                break;
            }
            if (c == '\r') {
                c = '\n';
            }
            out[written++] = (char)c;
        }
        if (written == 0 && g_pending_keyboard_signal != 0) {
            return err(EINTR);
        }
        return (int)written;
    }

    if (g_fds[fd].kind == FD_NULL) {
        return 0;
    }

    if (g_fds[fd].kind == FD_PIPE_R) {
        int pipe_id = g_fds[fd].pipe_id;
        if (pipe_id < 0 || pipe_id >= MAX_PIPES || !g_pipes[pipe_id].used) {
            return 0;
        }

        struct pipe_state* p = &g_pipes[pipe_id];
        if (p->size == 0) {
            return pipe_has_writer(pipe_id) ? err(EAGAIN) : 0;
        }

        size_t n = (count < p->size) ? count : p->size;
        size_t first = n;
        size_t start = p->read_off;
        if (first > PIPE_CAPACITY - start) {
            first = PIPE_CAPACITY - start;
        }
        memcpy(buf, &p->data[start], first);
        if (n > first) {
            memcpy((uint8_t*)buf + first, &p->data[0], n - first);
        }

        p->read_off = (p->read_off + n) % PIPE_CAPACITY;
        p->size -= n;
        return (int)n;
    }

    if (g_fds[fd].kind == FD_PIPE_W) {
        return err(EBADF);
    }

    if (g_fds[fd].kind == FD_DIR) {
        return err(EISDIR);
    }

    const uint8_t* data = g_fds[fd].entry.data;
    size_t size = g_fds[fd].entry.size;
    size_t off = g_fds[fd].offset;
    if (off >= size) {
        return 0;
    }

    size_t remain = size - off;
    size_t n = (count < remain) ? count : remain;
    memcpy(buf, data + off, n);
    g_fds[fd].offset += n;
    return (int)n;
}

static int sys_write(int fd, const void* buf, size_t count) {
    if (fd < 0 || fd >= MAX_FDS || g_fds[fd].kind == FD_FREE) {
        return err(EBADF);
    }

    if (g_fds[fd].kind == FD_NULL) {
        return (int)count;
    }

    if (g_fds[fd].kind == FD_PIPE_W) {
        int pipe_id = g_fds[fd].pipe_id;
        if (pipe_id < 0 || pipe_id >= MAX_PIPES || !g_pipes[pipe_id].used) {
            return err(EBADF);
        }

        struct pipe_state* p = &g_pipes[pipe_id];
        size_t avail = PIPE_CAPACITY - p->size;
        if (avail == 0) {
            return err(EAGAIN);
        }

        size_t n = (count < avail) ? count : avail;
        size_t write_off = (p->read_off + p->size) % PIPE_CAPACITY;
        size_t first = n;
        if (first > PIPE_CAPACITY - write_off) {
            first = PIPE_CAPACITY - write_off;
        }
        memcpy(&p->data[write_off], buf, first);
        if (n > first) {
            memcpy(&p->data[0], (const uint8_t*)buf + first, n - first);
        }
        p->size += n;
        return (int)n;
    }

    if (g_fds[fd].kind == FD_PIPE_R || g_fds[fd].kind == FD_DIR) {
        return err(EBADF);
    }

    if (g_fds[fd].kind != FD_TTY) {
        return err(EBADF);
    }

    const char* in = (const char*)buf;
    for (size_t i = 0; i < count; ++i) {
        console_putc(in[i]);
    }
    return (int)count;
}

static int sys_writev(int fd, const struct linux_iovec* iov, size_t iovcnt) {
    if (iovcnt > 1024) {
        return err(EINVAL);
    }

    int total = 0;
    for (size_t i = 0; i < iovcnt; ++i) {
        int n = sys_write(fd, (const void*)(uintptr_t)iov[i].base, (size_t)iov[i].len);
        if (n < 0) {
            return n;
        }
        total += n;
    }
    return total;
}

static int sys_readv(int fd, const struct linux_iovec* iov, size_t iovcnt) {
    if (iovcnt > 1024) {
        return err(EINVAL);
    }

    int total = 0;
    for (size_t i = 0; i < iovcnt; ++i) {
        int n = sys_read(fd, (void*)(uintptr_t)iov[i].base, (size_t)iov[i].len);
        if (n < 0) {
            return n;
        }
        total += n;
        if ((size_t)n < (size_t)iov[i].len) {
            break;
        }
    }
    return total;
}

static int64_t sys_lseek(int fd, int64_t offset, int whence) {
    if (fd < 0 || fd >= MAX_FDS || g_fds[fd].kind == FD_FREE) {
        return err(EBADF);
    }

    if (g_fds[fd].kind == FD_TTY || g_fds[fd].kind == FD_NULL || g_fds[fd].kind == FD_PIPE_R || g_fds[fd].kind == FD_PIPE_W) {
        return err(ESPIPE);
    }

    int64_t base = 0;
    if (whence == SEEK_SET) {
        base = 0;
    } else if (whence == SEEK_CUR) {
        base = (int64_t)g_fds[fd].offset;
    } else if (whence == SEEK_END) {
        base = (int64_t)g_fds[fd].entry.size;
    } else {
        return err(EINVAL);
    }

    int64_t new_off = base + offset;
    if (new_off < 0) {
        return err(EINVAL);
    }

    g_fds[fd].offset = (size_t)new_off;
    return new_off;
}

static int sys_pread64(int fd, void* buf, size_t count, int64_t offset) {
    if (fd < 0 || fd >= MAX_FDS || g_fds[fd].kind == FD_FREE) {
        return err(EBADF);
    }
    if (offset < 0) {
        return err(EINVAL);
    }
    if (g_fds[fd].kind == FD_TTY || g_fds[fd].kind == FD_NULL || g_fds[fd].kind == FD_PIPE_R || g_fds[fd].kind == FD_PIPE_W) {
        return err(ESPIPE);
    }
    if (g_fds[fd].kind == FD_DIR) {
        return err(EISDIR);
    }

    const uint8_t* data = g_fds[fd].entry.data;
    size_t size = g_fds[fd].entry.size;
    size_t off = (size_t)offset;
    if (off >= size) {
        return 0;
    }

    size_t remain = size - off;
    size_t n = (count < remain) ? count : remain;
    memcpy(buf, data + off, n);
    return (int)n;
}

static int sys_getdents64(int fd, void* dirp, size_t count) {
    if (fd < 0 || fd >= MAX_FDS || g_fds[fd].kind == FD_FREE) {
        return err(EBADF);
    }
    if (g_fds[fd].kind != FD_DIR) {
        return err(ENOTDIR);
    }

    size_t nchildren = collect_children(g_fds[fd].path, g_dirent_names, g_dirent_types);

    size_t idx = g_fds[fd].offset;
    size_t written = 0;

    while (idx < nchildren) {
        const char* name = g_dirent_names[idx];
        size_t name_len = strlen(name) + 1u;
        size_t reclen = (sizeof(struct linux_dirent64) + name_len + 7u) & ~7u;

        if (written + reclen > count) {
            break;
        }

        struct linux_dirent64* d = (struct linux_dirent64*)((uint8_t*)dirp + written);
        d->d_ino = (uint64_t)(idx + 1u);
        d->d_off = (int64_t)(idx + 1u);
        d->d_reclen = (uint16_t)reclen;
        d->d_type = g_dirent_types[idx];

        memcpy(d->d_name, name, name_len);
        memset((uint8_t*)d + sizeof(*d) + name_len, 0, reclen - sizeof(*d) - name_len);

        written += reclen;
        ++idx;
    }

    g_fds[fd].offset = idx;
    return (int)written;
}

static int64_t sys_sendfile(int out_fd, int in_fd, int64_t* offset, size_t count) {
    if (count == 0) {
        return 0;
    }
    if (in_fd < 0 || in_fd >= MAX_FDS || g_fds[in_fd].kind == FD_FREE) {
        return err(EBADF);
    }
    if (out_fd < 0 || out_fd >= MAX_FDS || g_fds[out_fd].kind == FD_FREE) {
        return err(EBADF);
    }

    if (g_fds[in_fd].kind == FD_DIR) {
        return err(EISDIR);
    }
    if (g_fds[in_fd].kind != FD_FILE && g_fds[in_fd].kind != FD_NULL) {
        return err(EINVAL);
    }

    if (g_fds[in_fd].kind == FD_NULL) {
        return 0;
    }

    int64_t off = (offset != NULL) ? *offset : (int64_t)g_fds[in_fd].offset;
    if (off < 0) {
        return err(EINVAL);
    }

    size_t size = g_fds[in_fd].entry.size;
    if ((size_t)off >= size) {
        return 0;
    }

    size_t avail = size - (size_t)off;
    size_t total = (count < avail) ? count : avail;
    size_t written = 0;
    const uint8_t* base = g_fds[in_fd].entry.data + (size_t)off;

    while (written < total) {
        size_t chunk = total - written;
        if (chunk > 4096u) {
            chunk = 4096u;
        }
        int w = sys_write(out_fd, base + written, chunk);
        if (w < 0) {
            return (written > 0) ? (int64_t)written : (int64_t)w;
        }
        if (w == 0) {
            break;
        }
        written += (size_t)w;
    }

    if (offset != NULL) {
        *offset = off + (int64_t)written;
    } else {
        g_fds[in_fd].offset = (size_t)(off + (int64_t)written);
    }
    return (int64_t)written;
}

static int sys_ioctl(int fd, uint64_t req, void* argp) {
    if (fd < 0 || fd >= MAX_FDS || g_fds[fd].kind == FD_FREE) {
        return err(EBADF);
    }

    if (g_fds[fd].kind != FD_TTY) {
        return err(ENOTTY);
    }

    if (req == TCGETS) {
        if (argp != NULL) {
            memset(argp, 0, 64);
        }
        return 0;
    }

    if (req == TIOCGWINSZ) {
        if (argp != NULL) {
            struct linux_winsize ws;
            ws.ws_row = 25;
            ws.ws_col = 80;
            ws.ws_xpixel = 0;
            ws.ws_ypixel = 0;
            memcpy(argp, &ws, sizeof(ws));
        }
        return 0;
    }

    return 0;
}

static int sys_fcntl(int fd, int cmd, uint64_t arg) {
    if (fd < 0 || fd >= MAX_FDS || g_fds[fd].kind == FD_FREE) {
        return err(EBADF);
    }

    switch (cmd) {
        case 0:  // F_DUPFD
        case 1030:  // F_DUPFD_CLOEXEC
        {
            int min_fd = (int)arg;
            int newfd = alloc_fd_from(min_fd);
            if (newfd < 0) {
                return newfd;
            }
            g_fds[newfd] = g_fds[fd];
            return newfd;
        }
        case 1:  // F_GETFD
            return 0;
        case 3:  // F_GETFL
            return (int)g_fds[fd].flags;
        case 2:  // F_SETFD
            return 0;
        case 4:  // F_SETFL
            g_fds[fd].flags = (g_fds[fd].flags & ~0xFFFFu) | ((uint32_t)arg & 0xFFFFu);
            return 0;
        default:
            return err(EINVAL);
    }
}

static int sys_dup_common(int oldfd, int wanted, bool exact) {
    if (oldfd < 0 || oldfd >= MAX_FDS || g_fds[oldfd].kind == FD_FREE) {
        return err(EBADF);
    }

    int newfd = wanted;
    if (!exact) {
        newfd = alloc_fd();
    }

    if (newfd < 0 || newfd >= MAX_FDS) {
        return err(EBADF);
    }

    if (newfd != oldfd && g_fds[newfd].kind != FD_FREE) {
        (void)sys_close(newfd);
    }

    g_fds[newfd] = g_fds[oldfd];
    return newfd;
}

static int sys_pipe2(int* pipefd, uint32_t flags) {
    if (pipefd == NULL) {
        return err(EFAULT);
    }
    if (flags != 0) {
        return err(EINVAL);
    }

    int rfd = alloc_fd();
    if (rfd < 0) {
        return rfd;
    }

    g_fds[rfd].kind = FD_DIR;  // temporary reservation until both ends are ready
    g_fds[rfd].pipe_id = -1;

    int wfd = alloc_fd();
    if (wfd < 0) {
        memset(&g_fds[rfd], 0, sizeof(g_fds[rfd]));
        g_fds[rfd].pipe_id = -1;
        return wfd;
    }

    int pipe_id = alloc_pipe_slot();
    if (pipe_id < 0) {
        memset(&g_fds[rfd], 0, sizeof(g_fds[rfd]));
        g_fds[rfd].pipe_id = -1;
        return pipe_id;
    }

    g_fds[rfd].kind = FD_PIPE_R;
    g_fds[rfd].flags = O_RDONLY;
    g_fds[rfd].offset = 0;
    g_fds[rfd].pipe_id = pipe_id;
    strcpy(g_fds[rfd].path, "pipe:[r]");

    g_fds[wfd].kind = FD_PIPE_W;
    g_fds[wfd].flags = O_WRONLY;
    g_fds[wfd].offset = 0;
    g_fds[wfd].pipe_id = pipe_id;
    strcpy(g_fds[wfd].path, "pipe:[w]");

    pipefd[0] = rfd;
    pipefd[1] = wfd;
    return 0;
}

static int sys_getcwd(char* buf, size_t size) {
    size_t len = strlen(g_cwd) + 1u;
    if (len > size) {
        return err(ENOMEM);
    }
    memcpy(buf, g_cwd, len);
    return (int)len;
}

static int sys_chdir(const char* path_user) {
    char path_input[128];
    if (copy_user_string(path_user, path_input, sizeof(path_input)) != 0) {
        return err(EINVAL);
    }

    char path[128];
    int r = make_absolute_path(AT_FDCWD, path_input, path, sizeof(path));
    if (r != 0) {
        return r;
    }

    uint32_t mode = 0;
    r = path_mode_size(path, &mode, NULL, NULL);
    if (r != 0) {
        return r;
    }
    if ((mode & S_IFMT) != S_IFDIR) {
        return err(ENOTDIR);
    }

    strncpy(g_cwd, path, sizeof(g_cwd));
    g_cwd[sizeof(g_cwd) - 1] = '\0';
    return 0;
}

static int resolve_user_path(int dirfd, const char* path_user, bool follow_final, char* out, size_t out_len) {
    char path_input[128];
    int cr = copy_user_string(path_user, path_input, sizeof(path_input));
    if (cr != 0) {
        return cr;
    }

    char abs_path[128];
    int ar = make_absolute_path(dirfd, path_input, abs_path, sizeof(abs_path));
    if (ar != 0) {
        return ar;
    }

    return resolve_symlinks(abs_path, out, out_len, follow_final);
}

static int sys_access_like(int dirfd, const char* path_user) {
    char path[128];
    int r = resolve_user_path(dirfd, path_user, true, path, sizeof(path));
    if (r != 0) {
        return r;
    }

    return path_mode_size(path, NULL, NULL, NULL);
}

static int sys_readlinkat(int dirfd, const char* path_user, char* out, size_t bufsz) {
    char path[128];
    int r = resolve_user_path(dirfd, path_user, false, path, sizeof(path));
    if (r != 0) {
        return r;
    }

    if (strcmp(path, "/proc/self/exe") == 0) {
        const char* target = "/bin/busybox";
        size_t n = strlen(target);
        if (n > bufsz) {
            n = bufsz;
        }
        memcpy(out, target, n);
        return (int)n;
    }

    struct initramfs_entry e;
    if (initramfs_find(path, &e) != 0 || (e.mode & S_IFMT) != S_IFLNK) {
        return err(ENOENT);
    }

    size_t n = e.size;
    if (n > bufsz) {
        n = bufsz;
    }
    memcpy(out, e.data, n);
    return (int)n;
}

static int sys_fstat(int fd, struct linux_stat* st) {
    if (fd < 0 || fd >= MAX_FDS || g_fds[fd].kind == FD_FREE) {
        return err(EBADF);
    }

    uint32_t mode = S_IFREG | 0644u;
    size_t size = 0;

    if (g_fds[fd].kind == FD_TTY) {
        mode = S_IFCHR | 0666u;
    } else if (g_fds[fd].kind == FD_NULL) {
        mode = S_IFCHR | 0666u;
    } else if (g_fds[fd].kind == FD_DIR) {
        mode = S_IFDIR | 0755u;
    } else if (g_fds[fd].kind == FD_PIPE_R || g_fds[fd].kind == FD_PIPE_W) {
        mode = S_IFIFO | 0600u;
    } else {
        mode = g_fds[fd].entry.mode;
        size = g_fds[fd].entry.size;
    }

    fill_stat(st, mode, size);
    return 0;
}

static int sys_newfstatat(int dirfd, const char* path_user, struct linux_stat* st) {
    char path[128];
    int r = resolve_user_path(dirfd, path_user, true, path, sizeof(path));
    if (r != 0) {
        return r;
    }

    uint32_t mode = 0;
    size_t size = 0;
    r = path_mode_size(path, &mode, &size, NULL);
    if (r != 0) {
        return r;
    }

    fill_stat(st, mode, size);
    return 0;
}

static int sys_statx(int dirfd, const char* path_user, struct linux_statx* stx) {
    char path[128];
    int r = resolve_user_path(dirfd, path_user, true, path, sizeof(path));
    if (r != 0) {
        return r;
    }

    uint32_t mode = 0;
    size_t size = 0;
    r = path_mode_size(path, &mode, &size, NULL);
    if (r != 0) {
        return r;
    }

    memset(stx, 0, sizeof(*stx));
    stx->stx_mask = 0xFFFu;
    stx->stx_mode = (uint16_t)mode;
    stx->stx_nlink = 1;
    stx->stx_uid = 0;
    stx->stx_gid = 0;
    stx->stx_size = size;
    stx->stx_blksize = 4096;
    stx->stx_blocks = (size + 511u) / 512u;
    stx->stx_ino = 1;
    return 0;
}

static int sys_stat_compat(const char* path_user, struct linux_stat* st, bool follow_final) {
    char path[128];
    int r = resolve_user_path(AT_FDCWD, path_user, follow_final, path, sizeof(path));
    if (r != 0) {
        return r;
    }

    uint32_t mode = 0;
    size_t size = 0;
    r = path_mode_size(path, &mode, &size, NULL);
    if (r != 0) {
        return r;
    }

    fill_stat(st, mode, size);
    return 0;
}

static int sys_uname(struct linux_utsname* uts) {
    memset(uts, 0, sizeof(*uts));
    strcpy(uts->sysname, "VibeOS");
    strcpy(uts->nodename, "vibe");
    strcpy(uts->release, "0.1");
    strcpy(uts->version, "monolithic-kernel-prototype");
    strcpy(uts->machine, "x86_64");
    strcpy(uts->domainname, "local");
    return 0;
}

static int sys_clock_gettime(struct linux_timespec* ts) {
    g_fake_time_ns += 1000000ull;
    ts->tv_sec = (int64_t)(g_fake_time_ns / 1000000000ull);
    ts->tv_nsec = (int64_t)(g_fake_time_ns % 1000000000ull);
    return 0;
}

static int64_t sys_mmap(uint64_t addr, size_t len, uint64_t flags) {
    if (len == 0) {
        return err(EINVAL);
    }

    const uint64_t align = 0x1000ull;
    uint64_t span = ((uint64_t)len + align - 1u) & ~(align - 1u);

    if (addr != 0 && (flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) != 0u) {
        uint64_t base = addr & ~(align - 1u);
        if (base < 0x1000ull || base + span >= USER_MMAP_LIMIT) {
            return err(ENOMEM);
        }
        memset((void*)(uintptr_t)base, 0, (size_t)span);
        return (int64_t)base;
    }

    uint64_t base = (g_mmap_next + align - 1u) & ~(align - 1u);
    if (base + span >= USER_MMAP_LIMIT) {
        return err(ENOMEM);
    }
    g_mmap_next = base + span;
    memset((void*)(uintptr_t)base, 0, (size_t)span);

    return (int64_t)base;
}

static int64_t sys_brk(uint64_t brk) {
    uint64_t old = g_brk_current;
    if (brk == 0) {
        return (int64_t)g_brk_current;
    }
    if (brk < USER_BRK_BASE || brk >= USER_MMAP_BASE) {
        return (int64_t)g_brk_current;
    }
    if (brk > old) {
        memset((void*)(uintptr_t)old, 0, (size_t)(brk - old));
    }
    g_brk_current = brk;
    return (int64_t)g_brk_current;
}

static int sys_getrandom(void* buf, size_t len) {
    uint8_t* out = (uint8_t*)buf;
    for (size_t i = 0; i < len; ++i) {
        out[i] = (uint8_t)xorshift64();
    }
    return (int)len;
}

static int sys_arch_prctl(uint64_t code, uint64_t addr) {
    if (code == ARCH_SET_FS) {
        if ((read_cr4() & (1ull << 16)) != 0ull) {
            write_fs_base_inst(addr);
        }
        wrmsr(IA32_FS_BASE, addr);
        return 0;
    }
    if (code == ARCH_GET_FS) {
        uint64_t fs_now = ((read_cr4() & (1ull << 16)) != 0ull) ? read_fs_base_inst() : rdmsr(IA32_FS_BASE);
        *(uint64_t*)(uintptr_t)addr = fs_now;
        return 0;
    }
    return err(EINVAL);
}

static uint64_t exec_stack_push_bytes(uint64_t sp, const void* data, size_t len) {
    sp -= len;
    memcpy((void*)(uintptr_t)sp, data, len);
    return sp;
}

static uint64_t exec_stack_push_u64(uint64_t sp, uint64_t value) {
    sp -= sizeof(uint64_t);
    *(uint64_t*)(uintptr_t)sp = value;
    return sp;
}

static uint64_t exec_stack_push_auxv(uint64_t sp, uint64_t type, uint64_t value) {
    sp = exec_stack_push_u64(sp, value);
    sp = exec_stack_push_u64(sp, type);
    return sp;
}

static int copy_user_str_array(uint64_t user_ptr, char out[][EXEC_STR_MAX], size_t max_out, size_t* count_out) {
    *count_out = 0;
    if (user_ptr == 0) {
        return 0;
    }

    const uint64_t* list = (const uint64_t*)(uintptr_t)user_ptr;
    for (size_t i = 0; i < max_out; ++i) {
        uint64_t p = list[i];
        if (p == 0) {
            *count_out = i;
            return 0;
        }
        int cr = copy_user_string((const char*)(uintptr_t)p, out[i], EXEC_STR_MAX);
        if (cr != 0) {
            return cr;
        }
    }

    return err(ENOMEM);
}

static int load_exec_image(const uint8_t* image, size_t image_size, uint64_t* entry_out, uint64_t* phdr_out, uint64_t* phent_out,
                           uint64_t* phnum_out, uint64_t* image_start_out, uint64_t* image_end_out) {
    if (image_size < sizeof(struct elf64_ehdr)) {
        return err(EINVAL);
    }

    const struct elf64_ehdr* eh = (const struct elf64_ehdr*)image;
    if (*(const uint32_t*)&eh->e_ident[0] != ELF_MAGIC || eh->e_type != ET_EXEC || eh->e_phentsize != sizeof(struct elf64_phdr)) {
        return err(EINVAL);
    }
    if (eh->e_phoff + (uint64_t)eh->e_phnum * sizeof(struct elf64_phdr) > image_size) {
        return err(EINVAL);
    }

    const struct elf64_phdr* ph = (const struct elf64_phdr*)(image + eh->e_phoff);
    uint64_t phdr_vaddr = 0;
    uint64_t image_start = UINT64_MAX;
    uint64_t image_end = 0;

    for (uint16_t i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type != PT_LOAD) {
            continue;
        }
        if (ph[i].p_offset + ph[i].p_filesz > image_size) {
            return err(EINVAL);
        }
        if (ph[i].p_vaddr + ph[i].p_memsz >= USER_ELF_LIMIT) {
            return err(ENOMEM);
        }

        uint8_t* dest = (uint8_t*)(uintptr_t)ph[i].p_vaddr;
        const uint8_t* src = image + ph[i].p_offset;
        memset(dest, 0, (size_t)ph[i].p_memsz);
        memcpy(dest, src, (size_t)ph[i].p_filesz);

        if (eh->e_phoff >= ph[i].p_offset && eh->e_phoff + (uint64_t)sizeof(struct elf64_phdr) <= ph[i].p_offset + ph[i].p_filesz) {
            phdr_vaddr = ph[i].p_vaddr + (eh->e_phoff - ph[i].p_offset);
        }

        if (ph[i].p_vaddr < image_start) {
            image_start = ph[i].p_vaddr;
        }
        uint64_t seg_end = ph[i].p_vaddr + ph[i].p_memsz;
        if (seg_end > image_end) {
            image_end = seg_end;
        }
    }

    if (image_start == UINT64_MAX || image_end <= image_start) {
        return err(EINVAL);
    }

    *entry_out = eh->e_entry;
    *phdr_out = phdr_vaddr;
    *phent_out = eh->e_phentsize;
    *phnum_out = eh->e_phnum;
    *image_start_out = image_start & ~0xFFFull;
    *image_end_out = (image_end + 0xFFFull) & ~0xFFFull;
    return 0;
}

static int build_exec_stack(const char* execfn, char argv[EXEC_MAX_ARGS][EXEC_STR_MAX], size_t argc,
                            char envp[EXEC_MAX_ENVS][EXEC_STR_MAX], size_t envc, uint64_t entry, uint64_t phdr, uint64_t phent,
                            uint64_t phnum, uint64_t* stack_out) {
    const char* platform = "x86_64";
    uint8_t at_random[16] = {
        0x12, 0x6E, 0xA7, 0x39, 0x55, 0xC8, 0x03, 0xF1, 0x88, 0x22, 0x74, 0xB5, 0xE1, 0x9C, 0x41, 0x0D,
    };

    uint64_t sp = USER_STACK_TOP;
    sp = exec_stack_push_bytes(sp, execfn, strlen(execfn) + 1u);
    uint64_t execfn_ptr = sp;

    sp = exec_stack_push_bytes(sp, platform, strlen(platform) + 1u);
    uint64_t platform_ptr = sp;

    sp = exec_stack_push_bytes(sp, at_random, sizeof(at_random));
    uint64_t at_random_ptr = sp;

    for (int i = (int)envc - 1; i >= 0; --i) {
        sp = exec_stack_push_bytes(sp, envp[i], strlen(envp[i]) + 1u);
        g_exec_env_ptrs[i] = sp;
    }
    for (int i = (int)argc - 1; i >= 0; --i) {
        sp = exec_stack_push_bytes(sp, argv[i], strlen(argv[i]) + 1u);
        g_exec_argv_ptrs[i] = sp;
    }

    sp &= ~0x0Full;
    sp = exec_stack_push_auxv(sp, 0, 0);
    sp = exec_stack_push_auxv(sp, 31, execfn_ptr);
    sp = exec_stack_push_auxv(sp, 51, 2048);
    sp = exec_stack_push_auxv(sp, 15, platform_ptr);
    sp = exec_stack_push_auxv(sp, 25, at_random_ptr);
    sp = exec_stack_push_auxv(sp, 16, 0);
    sp = exec_stack_push_auxv(sp, 26, 0);
    sp = exec_stack_push_auxv(sp, 33, 0);
    sp = exec_stack_push_auxv(sp, 23, 0);
    sp = exec_stack_push_auxv(sp, 17, 100);
    sp = exec_stack_push_auxv(sp, 8, 0);
    sp = exec_stack_push_auxv(sp, 7, 0);
    sp = exec_stack_push_auxv(sp, 14, 0);
    sp = exec_stack_push_auxv(sp, 13, 0);
    sp = exec_stack_push_auxv(sp, 12, 0);
    sp = exec_stack_push_auxv(sp, 11, 0);
    sp = exec_stack_push_auxv(sp, 9, entry);
    sp = exec_stack_push_auxv(sp, 6, 4096);
    sp = exec_stack_push_auxv(sp, 5, phnum);
    sp = exec_stack_push_auxv(sp, 4, phent);
    sp = exec_stack_push_auxv(sp, 3, phdr);

    sp = exec_stack_push_u64(sp, 0);
    for (int i = (int)envc - 1; i >= 0; --i) {
        sp = exec_stack_push_u64(sp, g_exec_env_ptrs[i]);
    }

    sp = exec_stack_push_u64(sp, 0);
    for (int i = (int)argc - 1; i >= 0; --i) {
        sp = exec_stack_push_u64(sp, g_exec_argv_ptrs[i]);
    }
    sp = exec_stack_push_u64(sp, argc);

    *stack_out = sp;
    return 0;
}

static int sys_execve(struct syscall_frame* frame, const char* path_user, uint64_t argv_user, uint64_t envp_user) {
    char path_input[128];
    int cr = copy_user_string(path_user, path_input, sizeof(path_input));
    if (cr != 0) {
        return cr;
    }

    char abs_path[128];
    int ar = make_absolute_path(AT_FDCWD, path_input, abs_path, sizeof(abs_path));
    if (ar != 0) {
        return ar;
    }

    char resolved_path[128];
    int rr = resolve_symlinks(abs_path, resolved_path, sizeof(resolved_path), true);
    if (rr != 0) {
        return rr;
    }

    struct initramfs_entry image_entry;
    if (initramfs_find(resolved_path, &image_entry) != 0 || (image_entry.mode & S_IFMT) != S_IFREG) {
        return err(ENOENT);
    }

    size_t argc = 0;
    size_t envc = 0;

    int argr = copy_user_str_array(argv_user, g_exec_argv_scratch, EXEC_MAX_ARGS, &argc);
    if (argr != 0) {
        return argr;
    }
    int envr = copy_user_str_array(envp_user, g_exec_env_scratch, EXEC_MAX_ENVS, &envc);
    if (envr != 0) {
        return envr;
    }

    if (argc == 0) {
        strncpy(g_exec_argv_scratch[0], abs_path, EXEC_STR_MAX);
        g_exec_argv_scratch[0][EXEC_STR_MAX - 1] = '\0';
        argc = 1;
    }

    uint64_t entry = 0;
    uint64_t phdr = 0;
    uint64_t phent = 0;
    uint64_t phnum = 0;
    uint64_t image_start = 0;
    uint64_t image_end = 0;
    int lr = load_exec_image(image_entry.data, image_entry.size, &entry, &phdr, &phent, &phnum, &image_start, &image_end);
    if (lr != 0) {
        return lr;
    }

    g_brk_current = USER_BRK_BASE;
    g_mmap_next = USER_MMAP_BASE;
    userland_set_image_span(image_start, image_end);

    uint64_t user_stack = 0;
    int sr = build_exec_stack(abs_path, g_exec_argv_scratch, argc, g_exec_env_scratch, envc, entry, phdr, phent, phnum, &user_stack);
    if (sr != 0) {
        return sr;
    }

    memset(frame, 0, sizeof(*frame));
    uint64_t* raw = (uint64_t*)(void*)frame;
    raw[IRET_SLOT_RIP] = entry;
    raw[IRET_SLOT_RSP] = user_stack;
    return 0;
}

static int sys_wait4(int pid, int* status, int options) {
    if ((options & ~WAIT_NOHANG) != 0) {
        return err(EINVAL);
    }
    if (pid < -1) {
        return err(ECHILD);
    }
    if (g_parent_pending && (pid == -1 || pid == g_pending_child_pid || pid == 0)) {
        return (options & WAIT_NOHANG) ? 0 : err(EAGAIN);
    }
    if (!g_wait_status_valid) {
        return err(ECHILD);
    }
    if (pid > 0 && pid != g_wait_status_pid) {
        return err(ECHILD);
    }

    if (status != NULL) {
        *status = g_wait_status_code;
    }

    int reaped = g_wait_status_pid;
    g_wait_status_valid = false;
    return reaped;
}

static int sys_set_tid_address(uint64_t tidptr) {
    g_tid_address = tidptr;
    return g_current_pid;
}

static int sys_fork_like(struct syscall_frame* frame, uint64_t clone_flags, uint64_t child_stack, uint64_t child_tid_ptr, uint64_t tls,
                         bool from_clone) {
    if (g_parent_pending) {
        return err(EAGAIN);
    }

    if (from_clone) {
        uint64_t allowed = CLONE_SIGNAL_MASK | CLONE_VM | CLONE_VFORK | CLONE_SETTLS | CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID;
        if ((clone_flags & ~allowed) != 0ull) {
            return err(EINVAL);
        }
        if ((clone_flags & CLONE_SIGNAL_MASK) != SIGCHLD) {
            return err(EINVAL);
        }
        if (child_stack != 0 && (child_stack < 0x1000ull || child_stack >= USER_MMAP_LIMIT)) {
            return err(EINVAL);
        }
        if ((clone_flags & (CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID)) != 0ull && child_tid_ptr == 0) {
            return err(EINVAL);
        }
    }

    int snap = snapshot_parent_memory(frame);
    if (snap != 0) {
        return snap;
    }

    memcpy(g_parent_fds, g_fds, sizeof(g_fds));
    memcpy(g_parent_cwd, g_cwd, sizeof(g_cwd));
    g_parent_brk_current = g_brk_current;
    g_parent_mmap_next = g_mmap_next;
    g_parent_tid_address = g_tid_address;
    g_parent_fs_base = read_fs_base_current();

    g_saved_parent_pid = g_current_pid;
    g_saved_parent_ppid = g_current_ppid;

    int child_pid = g_next_pid++;

    g_parent_frame = *frame;
    g_parent_frame.rax = (uint64_t)child_pid;

    uint64_t* raw = (uint64_t*)(void*)frame;
    g_parent_iret[0] = raw[IRET_SLOT_RIP];
    g_parent_iret[1] = raw[IRET_SLOT_CS];
    g_parent_iret[2] = raw[IRET_SLOT_RFLAGS];
    g_parent_iret[3] = raw[IRET_SLOT_RSP];
    g_parent_iret[4] = raw[IRET_SLOT_SS];

    if (from_clone && child_stack != 0) {
        raw[IRET_SLOT_RSP] = child_stack;
    }

    if (from_clone && (clone_flags & CLONE_SETTLS) != 0ull) {
        write_fs_base_current(tls);
    }
    if (from_clone && (clone_flags & CLONE_CHILD_SETTID) != 0ull) {
        *(uint32_t*)(uintptr_t)child_tid_ptr = (uint32_t)child_pid;
    }

    g_child_has_cleartid = from_clone && ((clone_flags & CLONE_CHILD_CLEARTID) != 0ull);
    g_child_cleartid_ptr = g_child_has_cleartid ? child_tid_ptr : 0;

    g_parent_pending = true;
    g_pending_child_pid = child_pid;
    g_wait_status_valid = false;
    g_current_pid = child_pid;
    g_current_ppid = g_saved_parent_pid;

    return 0;
}

static uint64_t sys_exit_common(struct syscall_frame* frame, uint64_t code) {
    if (g_tid_address != 0) {
        *(uint32_t*)(uintptr_t)g_tid_address = 0;
    }
    if (g_parent_pending && g_current_pid == g_pending_child_pid) {
        return resume_parent_after_child_exit(frame, code);
    }
    leave_user_mode(code);
    return 0;
}

void syscall_init(void) {
    memset(g_fds, 0, sizeof(g_fds));
    memset(g_parent_fds, 0, sizeof(g_parent_fds));

    for (int i = 0; i < 3; ++i) {
        g_fds[i].kind = FD_TTY;
        g_fds[i].flags = O_RDWR;
        g_fds[i].offset = 0;
        g_fds[i].pipe_id = -1;
        strcpy(g_fds[i].path, "/dev/tty");
    }

    strcpy(g_cwd, "/");
    g_brk_current = USER_BRK_BASE;
    g_mmap_next = USER_MMAP_BASE;
    g_current_pid = 1;
    g_current_ppid = 0;
    g_next_pid = 2;
    g_parent_pending = false;
    g_pending_child_pid = 0;
    g_child_has_cleartid = false;
    g_child_cleartid_ptr = 0;
    g_wait_status_valid = false;
    g_wait_status_pid = 0;
    g_wait_status_code = 0;
    g_pending_keyboard_signal = 0;
    g_tid_address = 0;
    memset(g_pipes, 0, sizeof(g_pipes));

    g_rng_state ^= read_tsc();

    /*
     * Enable amd64 SYSCALL/SYSRET entry and route to syscall_entry.
     * We return via iretq in asm, but userland uses the Linux syscall ABI.
     */
    uint64_t efer = rdmsr(IA32_EFER);
    wrmsr(IA32_EFER, efer | EFER_SCE);

    uint64_t star = ((uint64_t)0x20u << 48) | ((uint64_t)0x08u << 32);
    wrmsr(IA32_STAR, star);
    wrmsr(IA32_LSTAR, (uint64_t)(uintptr_t)syscall_entry);
    wrmsr(IA32_FMASK, 0x200ull);  // Mask IF on entry.

}

uint64_t syscall_dispatch(struct syscall_frame* frame) {
    uint64_t nr = frame->rax;
    uint64_t a0 = frame->rdi;
    uint64_t a1 = frame->rsi;
    uint64_t a2 = frame->rdx;
    uint64_t a3 = frame->r10;
    uint64_t a4 = frame->r8;
    uint64_t a5 = frame->r9;

    (void)a4;
    (void)a5;

    if (g_pending_keyboard_signal != 0 && g_parent_pending && g_current_pid == g_pending_child_pid) {
        int signal = take_keyboard_signal();
        if (is_keyboard_signal(signal)) {
            return resume_parent_after_child_signal(frame, signal);
        }
    }

    switch (nr) {
        case 0:
        {
            int r = sys_read((int)a0, (void*)(uintptr_t)a1, (size_t)a2);
            if (r == err(EINTR)) {
                int signal = take_keyboard_signal();
                if (is_keyboard_signal(signal) && g_parent_pending && g_current_pid == g_pending_child_pid) {
                    return resume_parent_after_child_signal(frame, signal);
                }
            }
            return (uint64_t)r;
        }
        case 1:
            return (uint64_t)sys_write((int)a0, (const void*)(uintptr_t)a1, (size_t)a2);
        case 2:
            return (uint64_t)sys_openat(AT_FDCWD, (const char*)(uintptr_t)a0, (uint32_t)a1);
        case 3:
            return (uint64_t)sys_close((int)a0);
        case 4:
            return (uint64_t)sys_stat_compat((const char*)(uintptr_t)a0, (struct linux_stat*)(uintptr_t)a1, true);
        case 5:
            return (uint64_t)sys_fstat((int)a0, (struct linux_stat*)(uintptr_t)a1);
        case 6:
            return (uint64_t)sys_stat_compat((const char*)(uintptr_t)a0, (struct linux_stat*)(uintptr_t)a1, false);
        case 8:
            return (uint64_t)sys_lseek((int)a0, (int64_t)a1, (int)a2);
        case 9:
            return (uint64_t)sys_mmap(a0, (size_t)a1, a3);
        case 10:
            return 0;
        case 11:
            return 0;
        case 12:
            return (uint64_t)sys_brk(a0);
        case 13:
            return 0;
        case 14:
            return 0;
        case 16:
            return (uint64_t)sys_ioctl((int)a0, a1, (void*)(uintptr_t)a2);
        case 17:
            return (uint64_t)sys_pread64((int)a0, (void*)(uintptr_t)a1, (size_t)a2, (int64_t)a3);
        case 19:
        {
            int r = sys_readv((int)a0, (const struct linux_iovec*)(uintptr_t)a1, (size_t)a2);
            if (r == err(EINTR)) {
                int signal = take_keyboard_signal();
                if (is_keyboard_signal(signal) && g_parent_pending && g_current_pid == g_pending_child_pid) {
                    return resume_parent_after_child_signal(frame, signal);
                }
            }
            return (uint64_t)r;
        }
        case 20:
            return (uint64_t)sys_writev((int)a0, (const struct linux_iovec*)(uintptr_t)a1, (size_t)a2);
        case 21:
            return (uint64_t)sys_access_like(AT_FDCWD, (const char*)(uintptr_t)a0);
        case 22:
            return (uint64_t)sys_pipe2((int*)(uintptr_t)a0, 0);
        case 28:
            return 0;
        case 32:
            return (uint64_t)sys_dup_common((int)a0, 0, false);
        case 33:
            return (uint64_t)sys_dup_common((int)a0, (int)a1, true);
        case 39:
            return (uint64_t)g_current_pid;
        case 40:
            return (uint64_t)sys_sendfile((int)a0, (int)a1, (int64_t*)(uintptr_t)a2, (size_t)a3);
        case 56:
            return (uint64_t)sys_fork_like(frame, a0, a1, a3, a4, true);
        case 57:
            return (uint64_t)sys_fork_like(frame, 0, 0, 0, 0, false);
        case 58:
            return (uint64_t)sys_fork_like(frame, 0, 0, 0, 0, false);
        case 59:
            return (uint64_t)sys_execve(frame, (const char*)(uintptr_t)a0, a1, a2);
        case 60:
            return sys_exit_common(frame, a0);
        case 61:
            return (uint64_t)sys_wait4((int)a0, (int*)(uintptr_t)a1, (int)a2);
        case 63:
            return (uint64_t)sys_uname((struct linux_utsname*)(uintptr_t)a0);
        case 72:
            return (uint64_t)sys_fcntl((int)a0, (int)a1, a2);
        case 79:
            return (uint64_t)sys_getcwd((char*)(uintptr_t)a0, (size_t)a1);
        case 80:
            return (uint64_t)sys_chdir((const char*)(uintptr_t)a0);
        case 89:
            return (uint64_t)sys_readlinkat(AT_FDCWD, (const char*)(uintptr_t)a0, (char*)(uintptr_t)a1, (size_t)a2);
        case 102:
        case 104:
        case 107:
        case 108:
            return 0;
        case 110:
            return (uint64_t)g_current_ppid;
        case 131:
            return 0;
        case 157:
            return 0;
        case 158:
            return (uint64_t)sys_arch_prctl(a0, a1);
        case 186:
            return (uint64_t)g_current_pid;
        case 202:
            return 0;
        case 217:
            return (uint64_t)sys_getdents64((int)a0, (void*)(uintptr_t)a1, (size_t)a2);
        case 218:
            return (uint64_t)sys_set_tid_address(a0);
        case 228:
            return (uint64_t)sys_clock_gettime((struct linux_timespec*)(uintptr_t)a1);
        case 231:
            return sys_exit_common(frame, a0);
        case 257:
            return (uint64_t)sys_openat((int)a0, (const char*)(uintptr_t)a1, (uint32_t)a2);
        case 262:
            return (uint64_t)sys_newfstatat((int)a0, (const char*)(uintptr_t)a1, (struct linux_stat*)(uintptr_t)a2);
        case 267:
            return (uint64_t)sys_readlinkat((int)a0, (const char*)(uintptr_t)a1, (char*)(uintptr_t)a2, (size_t)a3);
        case 269:
            return (uint64_t)sys_access_like((int)a0, (const char*)(uintptr_t)a1);
        case 273:
            return 0;
        case 292:
            return (uint64_t)sys_dup_common((int)a0, (int)a1, true);
        case 293:
            return (uint64_t)sys_pipe2((int*)(uintptr_t)a0, (uint32_t)a1);
        case 302:
            return 0;
        case 318:
            return (uint64_t)sys_getrandom((void*)(uintptr_t)a0, (size_t)a1);
        case 332:
            return (uint64_t)sys_statx((int)a0, (const char*)(uintptr_t)a1, (struct linux_statx*)(uintptr_t)a4);
        case 334:
            return (uint64_t)err(ENOSYS);
        case 439:
            return (uint64_t)sys_access_like((int)a0, (const char*)(uintptr_t)a1);
        default:
            return (uint64_t)err(ENOSYS);
    }
}
