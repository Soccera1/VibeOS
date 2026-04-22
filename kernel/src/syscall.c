#include "syscall.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common.h"
#include "console.h"
#include "fs.h"
#include "input.h"
#include "io.h"
#include "kmalloc.h"
#include "power.h"
#include "process.h"
#include "string.h"
#include "userland.h"
#include "vm.h"

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
#define O_NONBLOCK 0x800u
#define O_DIRECTORY 0x10000u

#define FD_CLOEXEC 1u

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
#define TCSETS 0x5402u
#define TCSETSW 0x5403u
#define TCSETSF 0x5404u
#define TIOCGPGRP 0x540Fu
#define TIOCSPGRP 0x5410u
#define TIOCGWINSZ 0x5413u
#define FIONREAD 0x541Bu
#define FBIOGET_VSCREENINFO 0x4600u
#define FBIOPUT_VSCREENINFO 0x4601u
#define FBIOGET_FSCREENINFO 0x4602u
#define FBIOGETCMAP 0x4604u
#define FBIOPUTCMAP 0x4605u
#define FBIOPAN_DISPLAY 0x4606u
#define FBIOBLANK 0x4611u

#define FB_TYPE_PACKED_PIXELS 0u
#define FB_VISUAL_TRUECOLOR 2u
#define FB_ACCEL_NONE 0u

#define POLLIN 0x0001
#define POLLPRI 0x0002
#define POLLOUT 0x0004
#define POLLERR 0x0008
#define POLLHUP 0x0010
#define POLLNVAL 0x0020

#define MAX_FDS 64
#define MAX_CHILDREN 256
#define MAP_SHARED 0x01u
#define MAP_PRIVATE 0x02u
#define MAP_FIXED 0x10u
#define MAP_ANONYMOUS 0x20u
#define MAP_FIXED_NOREPLACE 0x100000u

#define ENOSYS 38
#define ENOENT 2
#define EINTR 4
#define ECHILD 10
#define EAGAIN 11
#define EBADF 9
#define EFAULT 14
#define EINVAL 22
#define ENODEV 19
#define ENOTTY 25
#define ENOTDIR 20
#define EISDIR 21
#define ENOTSUP 95
#define ESPIPE 29
#define ENOMEM 12
#define EEXIST 17
#define EROFS 30
#define ESRCH 3
#define EPERM 1
#define EPIPE 32

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
#define SIGKILL 9u
#define SIGTERM 15u
#define SIGSTOP 19u
#define SIGCONT 18u
#define SIGUSR1 10u
#define SIGUSR2 12u
#define SIGSEGV 11u
#define SIGPIPE 13u
#define SIGALRM 14u
#define SIGBUS 7u
#define SIGFPE 8u
#define SIGILL 4u
#define SIGQUIT 3u
#define SIGTRAP 5u
#define SIGABRT 6u
#define SIGTTIN 21u
#define SIGTTOU 22u
#define NSIG 64u

#define WAIT_NOHANG 1u
#define WAIT_UNTRACED 2u
#define WAIT_CONTINUED 8u

#define SIG_DFL ((void*)0)
#define SIG_IGN ((void*)1)

#define SA_NOCLDSTOP 0x00000001u
#define SA_NOCLDWAIT 0x00000002u
#define SA_SIGINFO 0x00000004u
#define SA_ONSTACK 0x08000000u
#define SA_RESTART 0x10000000u
#define SA_NODEFER 0x40000000u
#define SA_RESETHAND 0x80000000u

#define SIG_BLOCK 0
#define SIG_UNBLOCK 1
#define SIG_SETMASK 2

#define MAX_ZOMBIES 64
#define MAX_PENDING_SIGNALS 32
#define SELECT_FDSET_BYTES 128u

#define NCCS 19u
#define VINTR 0u
#define VQUIT 1u
#define VERASE 2u
#define VKILL 3u
#define VEOF 4u
#define VTIME 5u
#define VMIN 6u
#define VSWTC 7u
#define VSTART 8u
#define VSTOP 9u
#define VSUSP 10u
#define VEOL 11u
#define VREPRINT 12u
#define VDISCARD 13u
#define VWERASE 14u
#define VLNEXT 15u
#define VEOL2 16u

#define IGNBRK 0x00000001u
#define BRKINT 0x00000002u
#define ICRNL 0x00000100u
#define IXON 0x00000400u

#define OPOST 0x00000001u
#define ONLCR 0x00000004u

#define CS8 0x00000030u
#define CREAD 0x00000080u

#define ISIG 0x00000001u
#define ICANON 0x00000002u
#define ECHO 0x00000008u
#define ECHOE 0x00000010u
#define ECHOK 0x00000020u
#define ECHOCTL 0x00000200u
#define ECHOKE 0x00000800u
#define IEXTEN 0x00008000u

#define RLIM_INFINITY (~0ull)
#define APPROX_TSC_CYCLES_PER_USEC 2000ull

#define MAX_PIPES 64
#define PIPE_CAPACITY 65536

#define EXEC_MAX_ARGS 64
#define EXEC_MAX_ENVS 64
/*
 * Bash exports a long LS_COLORS value by default, so a tiny per-string exec
 * scratch buffer causes every external command to fail after shell startup.
 */
#define EXEC_STR_MAX 4096
#define EXEC_MAX_SYMLINKS 8

#define ELF_MAGIC 0x464C457Fu
#define ET_EXEC 2u
#define PT_LOAD 1u

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

struct linux_timeval {
    int64_t tv_sec;
    int64_t tv_usec;
};

struct linux_termios {
    uint32_t c_iflag;
    uint32_t c_oflag;
    uint32_t c_cflag;
    uint32_t c_lflag;
    uint8_t c_line;
    uint8_t c_cc[19];
};

struct linux_pselect_sigmask {
    uint64_t sigmask;
    uint64_t sigsetsize;
};

struct fb_fix_screeninfo {
    char id[16];
    unsigned long smem_start;
    uint32_t smem_len;
    uint32_t type;
    uint32_t type_aux;
    uint32_t visual;
    uint16_t xpanstep;
    uint16_t ypanstep;
    uint16_t ywrapstep;
    uint32_t line_length;
    unsigned long mmio_start;
    uint32_t mmio_len;
    uint32_t accel;
    uint16_t capabilities;
    uint16_t reserved[2];
};

struct fb_bitfield {
    uint32_t offset;
    uint32_t length;
    uint32_t msb_right;
};

struct fb_var_screeninfo {
    uint32_t xres;
    uint32_t yres;
    uint32_t xres_virtual;
    uint32_t yres_virtual;
    uint32_t xoffset;
    uint32_t yoffset;
    uint32_t bits_per_pixel;
    uint32_t grayscale;
    struct fb_bitfield red;
    struct fb_bitfield green;
    struct fb_bitfield blue;
    struct fb_bitfield transp;
    uint32_t nonstd;
    uint32_t activate;
    uint32_t height;
    uint32_t width;
    uint32_t accel_flags;
    uint32_t pixclock;
    uint32_t left_margin;
    uint32_t right_margin;
    uint32_t upper_margin;
    uint32_t lower_margin;
    uint32_t hsync_len;
    uint32_t vsync_len;
    uint32_t sync;
    uint32_t vmode;
    uint32_t rotate;
    uint32_t colorspace;
    uint32_t reserved[4];
};

struct fb_cmap {
    uint32_t start;
    uint32_t len;
    uint16_t* red;
    uint16_t* green;
    uint16_t* blue;
    uint16_t* transp;
};

struct linux_rlimit {
    uint64_t rlim_cur;
    uint64_t rlim_max;
};

struct linux_sigaction {
    void* handler;
    uint64_t flags;
    void* restorer;
    uint64_t mask;
};

struct linux_pollfd {
    int fd;
    int16_t events;
    int16_t revents;
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
    FD_FB,
    FD_PIPE_R,
    FD_PIPE_W,
};

struct fd_state {
    enum fd_kind kind;
    uint32_t flags;
    uint32_t fd_flags;
    size_t offset;
    int pipe_id;
    struct fs_entry entry;
    char path[FS_MAX_PATH];
};

struct pipe_state {
    bool used;
    size_t read_off;
    size_t size;
    uint8_t data[PIPE_CAPACITY];
};

static struct fd_state g_fds[MAX_FDS];
static char g_cwd[128] = "/";
static uint64_t g_brk_current = VM_USER_BRK_BASE;
static uint64_t g_mmap_next = VM_USER_MMAP_BASE;
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
static int g_current_pgid = 1;
static int g_current_sid = 1;
static int g_pending_keyboard_signal;
static struct pipe_state g_pipes[MAX_PIPES];
static uint64_t g_tid_address;
static uint16_t g_fb_cmap_red[256];
static uint16_t g_fb_cmap_green[256];
static uint16_t g_fb_cmap_blue[256];
static uint16_t g_fb_cmap_transp[256];

struct zombie_info {
    bool valid;
    int pid;
    int ppid;
    int pgid;
    int exit_code;
    int exit_status;
};

static struct zombie_info g_zombies[MAX_ZOMBIES];
static int g_zombie_count = 0;

static struct sigaction_data g_sig_actions[NSIG];
static uint64_t g_sig_mask = 0;
static int g_pending_signals[MAX_PENDING_SIGNALS];
static int g_pending_signal_count = 0;
static uint32_t g_umask = 022u;
static struct linux_termios g_tty_termios;
static int g_terminal_fg_pgrp = 1;
static int g_scheduler_index = 0;

static void add_zombie(int pid, int ppid, int pgid, int exit_code, int exit_status);
static void remove_zombie(int idx);
static struct process* current_process(void);
static int save_live_process(struct process* proc, struct syscall_frame* frame);
static int try_complete_wait4(struct process* proc);
static int try_complete_tty_read(struct process* proc);
static int try_complete_pipe_read(struct process* proc);
static int try_complete_pipe_write(struct process* proc);
static int try_complete_select(struct process* proc);
static int try_complete_nanosleep(struct process* proc);
static uint64_t schedule_away(struct syscall_frame* frame);
static int signal_process_group(int pgid, int sig);
static int map_exec_segment(struct process* proc, uint64_t vaddr, size_t memsz, const void* src, size_t filesz);
static void close_cloexec_fds(void);
static int sys_close(int fd);

__attribute__((noreturn)) static void do_shutdown(void);
__attribute__((noreturn)) static void do_halt(void);
__attribute__((noreturn)) static void do_reboot(void);

extern void leave_user_mode(uint64_t code) __attribute__((noreturn));
extern void syscall_entry(void);

static int normalize_path(const char* input, char* out, size_t out_len);
static int join_path(const char* base, const char* leaf, char* out, size_t out_len);

static int err(int code) {
    return -code;
}

static void init_default_tty_termios(void) {
    memset(&g_tty_termios, 0, sizeof(g_tty_termios));
    g_tty_termios.c_iflag = IGNBRK | BRKINT | ICRNL | IXON;
    g_tty_termios.c_oflag = OPOST | ONLCR;
    g_tty_termios.c_cflag = CREAD | CS8;
    g_tty_termios.c_lflag = ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN;
    g_tty_termios.c_cc[VINTR] = 3;
    g_tty_termios.c_cc[VQUIT] = 28;
    g_tty_termios.c_cc[VERASE] = 127;
    g_tty_termios.c_cc[VKILL] = 21;
    g_tty_termios.c_cc[VEOF] = 4;
    g_tty_termios.c_cc[VMIN] = 1;
    g_tty_termios.c_cc[VSTART] = 17;
    g_tty_termios.c_cc[VSTOP] = 19;
    g_tty_termios.c_cc[VSUSP] = 26;
    g_tty_termios.c_cc[VREPRINT] = 18;
    g_tty_termios.c_cc[VDISCARD] = 15;
    g_tty_termios.c_cc[VWERASE] = 23;
    g_tty_termios.c_cc[VLNEXT] = 22;
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

static bool tty_is_foreground_group(void) {
    return g_terminal_fg_pgrp == g_current_pgid;
}

static void service_keyboard_signal_for_tty(void) {
    int signal = input_peek_signal();
    if (signal == 0) {
        return;
    }

    if (tty_is_foreground_group()) {
        queue_keyboard_signal(input_poll_signal());
        return;
    }

    (void)input_poll_signal();
}

static bool fd_is_nonblocking(int fd) {
    return (g_fds[fd].flags & O_NONBLOCK) != 0u;
}

static bool tty_input_ready(void) {
    service_keyboard_signal_for_tty();
    return g_pending_keyboard_signal != 0 || input_char_ready();
}

static int handle_pending_keyboard_signal(struct syscall_frame* frame) {
    if (g_pending_keyboard_signal == 0) {
        return 0;
    }

    int sig = take_keyboard_signal();
    struct process* current = current_process();
    if (current != NULL && frame != NULL) {
        int sr = save_live_process(current, frame);
        if (sr != 0) {
            return sr;
        }
    }

    int r = signal_process_group(g_terminal_fg_pgrp, sig);
    if (r != 0) {
        return err(EINTR);
    }

    current = current_process();
    if (current != NULL && (current->state == PROCESS_STOPPED || current->state == PROCESS_ZOMBIE)) {
        return (int)schedule_away(frame);
    }

    return err(EINTR);
}

static int tty_signal_for_char(int c) {
    if ((g_tty_termios.c_lflag & ISIG) == 0u) {
        return 0;
    }
    if (c == (int)g_tty_termios.c_cc[VINTR]) {
        return (int)SIGINT;
    }
    if (c == (int)g_tty_termios.c_cc[VQUIT]) {
        return (int)SIGQUIT;
    }
    if (c == (int)g_tty_termios.c_cc[VSUSP]) {
        return (int)SIGTSTP;
    }
    return 0;
}

static int tty_deliver_signal(int sig, struct syscall_frame* frame) {
    struct process* current = current_process();
    if (current != NULL && frame != NULL) {
        int sr = save_live_process(current, frame);
        if (sr != 0) {
            return sr;
        }
    }

    int r = signal_process_group(g_terminal_fg_pgrp, sig);
    if (r != 0) {
        return err(EINTR);
    }

    current = current_process();
    if (current != NULL && (current->state == PROCESS_STOPPED || current->state == PROCESS_ZOMBIE)) {
        return (int)schedule_away(frame);
    }

    return err(EINTR);
}

static int tty_normalize_char(int c) {
    if (c == '\r' && (g_tty_termios.c_iflag & ICRNL) != 0u) {
        return '\n';
    }
    return c;
}

static uint64_t timeout_to_tsc_cycles(int64_t sec, int64_t nsec) {
    if (sec <= 0 && nsec <= 0) {
        return 0;
    }

    uint64_t total_usec = 0;
    if (sec > 0) {
        if ((uint64_t)sec > UINT64_MAX / 1000000ull) {
            return UINT64_MAX;
        }
        total_usec = (uint64_t)sec * 1000000ull;
    }
    if (nsec > 0) {
        total_usec += (uint64_t)nsec / 1000ull;
    }
    if (total_usec > UINT64_MAX / APPROX_TSC_CYCLES_PER_USEC) {
        return UINT64_MAX;
    }
    return total_usec * APPROX_TSC_CYCLES_PER_USEC;
}

static bool timeout_expired(uint64_t start, uint64_t budget) {
    if (budget == UINT64_MAX) {
        return false;
    }
    return (read_tsc() - start) >= budget;
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

static void capture_user_context(struct process* proc, struct syscall_frame* frame) {
    if (proc == NULL || frame == NULL) {
        return;
    }

    proc->saved_frame = *frame;
    uint64_t* raw = (uint64_t*)(void*)frame;
    proc->saved_iret[0] = raw[IRET_SLOT_RIP];
    proc->saved_iret[1] = raw[IRET_SLOT_CS];
    proc->saved_iret[2] = raw[IRET_SLOT_RFLAGS];
    proc->saved_iret[3] = raw[IRET_SLOT_RSP];
    proc->saved_iret[4] = raw[IRET_SLOT_SS];
    proc->has_saved_context = true;
}

static void restore_user_context(const struct process* proc, struct syscall_frame* frame) {
    if (proc == NULL || frame == NULL || !proc->has_saved_context) {
        return;
    }

    *frame = proc->saved_frame;
    uint64_t* raw = (uint64_t*)(void*)frame;
    raw[IRET_SLOT_RIP] = proc->saved_iret[0];
    raw[IRET_SLOT_CS] = proc->saved_iret[1];
    raw[IRET_SLOT_RFLAGS] = proc->saved_iret[2];
    raw[IRET_SLOT_RSP] = proc->saved_iret[3];
    raw[IRET_SLOT_SS] = proc->saved_iret[4];
}

static int save_live_process(struct process* proc, struct syscall_frame* frame) {
    if (proc == NULL || frame == NULL) {
        return err(EINVAL);
    }

    capture_user_context(proc, frame);

    proc->ppid = g_current_ppid;
    proc->pgid = g_current_pgid;
    proc->sid = g_current_sid;
    proc->brk_current = g_brk_current;
    proc->mmap_next = g_mmap_next;
    proc->tid_address = g_tid_address;
    proc->fs_base = read_fs_base_current();
    proc->umask = g_umask;

    memcpy(proc->fds, g_fds, sizeof(g_fds));
    memcpy(proc->cwd, g_cwd, sizeof(g_cwd));
    memcpy(proc->sig_actions, g_sig_actions, sizeof(g_sig_actions));
    proc->sig_mask = g_sig_mask;
    memcpy(proc->pending_signals, g_pending_signals, sizeof(g_pending_signals));
    proc->pending_count = g_pending_signal_count;

    uint64_t image_start = 0;
    uint64_t image_end = 0;
    userland_get_image_span(&image_start, &image_end);
    proc->image_start = image_start;
    proc->image_end = image_end;

    return 0;
}

static void sync_current_process_runtime(void) {
    struct process* proc = current_process();
    if (proc == NULL) {
        return;
    }

    proc->ppid = g_current_ppid;
    proc->pgid = g_current_pgid;
    proc->sid = g_current_sid;
    proc->brk_current = g_brk_current;
    proc->mmap_next = g_mmap_next;
    proc->tid_address = g_tid_address;
    proc->fs_base = read_fs_base_current();
    proc->umask = g_umask;
    memcpy(proc->fds, g_fds, sizeof(g_fds));
    memcpy(proc->cwd, g_cwd, sizeof(g_cwd));
    memcpy(proc->sig_actions, g_sig_actions, sizeof(g_sig_actions));
    proc->sig_mask = g_sig_mask;
    memcpy(proc->pending_signals, g_pending_signals, sizeof(g_pending_signals));
    proc->pending_count = g_pending_signal_count;
    userland_get_image_span(&proc->image_start, &proc->image_end);
}

static void load_process_runtime(struct process* proc) {
    vm_space_activate(&proc->vm);
    process_set_current(proc);
    g_current_pid = proc->pid;
    g_current_ppid = proc->ppid;
    g_current_pgid = proc->pgid;
    g_current_sid = proc->sid;
    g_brk_current = proc->brk_current;
    g_mmap_next = proc->mmap_next;
    g_tid_address = proc->tid_address;
    g_umask = proc->umask;

    memcpy(g_fds, proc->fds, sizeof(g_fds));
    memcpy(g_cwd, proc->cwd, sizeof(g_cwd));
    memcpy(g_sig_actions, proc->sig_actions, sizeof(g_sig_actions));
    g_sig_mask = proc->sig_mask;
    memcpy(g_pending_signals, proc->pending_signals, sizeof(g_pending_signals));
    g_pending_signal_count = proc->pending_count;

    userland_set_image_span(proc->image_start, proc->image_end);
    write_fs_base_current(proc->fs_base);
}

static struct process* current_process(void) {
    return process_current();
}

static bool has_other_runnable_process(const struct process* current) {
    for (int i = 0; i < MAX_PROCESSES; ++i) {
        struct process* proc = process_at(i);
        if (proc == NULL || proc->state != PROCESS_RUNNABLE) {
            continue;
        }
        if (proc != current) {
            return true;
        }
    }
    return false;
}

static struct process* pick_next_runnable_process(const struct process* current) {
    for (int i = 0; i < MAX_PROCESSES; ++i) {
        g_scheduler_index = (g_scheduler_index + 1) % MAX_PROCESSES;
        struct process* proc = process_at(g_scheduler_index);
        if (proc == NULL || proc->state != PROCESS_RUNNABLE || !proc->has_saved_context) {
            continue;
        }
        if (proc == current) {
            continue;
        }
        return proc;
    }

    if (current != NULL && current->state == PROCESS_RUNNABLE && current->has_saved_context) {
        return (struct process*)current;
    }

    return NULL;
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

        struct fs_entry e;
        if (fs_lookup(current, &e) != 0) {
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
        int n = fs_readlink(&e, target_raw, sizeof(target_raw) - 1u);
        if (n < 0) {
            return n;
        }
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

static bool pipe_is_referenced_in_process_fd_table(const struct process_fd* fds, int pipe_id) {
    for (int fd = 0; fd < PROCESS_MAX_FDS; ++fd) {
        if ((fds[fd].kind == FD_PIPE_R || fds[fd].kind == FD_PIPE_W) && fds[fd].pipe_id == pipe_id) {
            return true;
        }
    }
    return false;
}

static bool process_holds_pipe_refs(const struct process* proc) {
    return proc != NULL && proc->state != PROCESS_FREE && proc->state != PROCESS_ZOMBIE;
}

static bool pipe_is_referenced(int pipe_id) {
    if (pipe_is_referenced_in_fd_table(g_fds, pipe_id)) {
        return true;
    }
    for (int i = 0; i < MAX_PROCESSES; ++i) {
        struct process* proc = process_at(i);
        if (proc == current_process() || !process_holds_pipe_refs(proc)) {
            continue;
        }
        if (pipe_is_referenced_in_process_fd_table(proc->fds, pipe_id)) {
            return true;
        }
    }
    return false;
}

static bool pipe_has_writer_in_process_fd_table(const struct process_fd* fds, int pipe_id) {
    for (int fd = 0; fd < PROCESS_MAX_FDS; ++fd) {
        if (fds[fd].kind == FD_PIPE_W && fds[fd].pipe_id == pipe_id) {
            return true;
        }
    }
    return false;
}

static bool pipe_has_writer(int pipe_id) {
    for (int fd = 0; fd < MAX_FDS; ++fd) {
        if (g_fds[fd].kind == FD_PIPE_W && g_fds[fd].pipe_id == pipe_id) {
            return true;
        }
    }
    for (int i = 0; i < MAX_PROCESSES; ++i) {
        struct process* proc = process_at(i);
        if (proc == current_process() || !process_holds_pipe_refs(proc)) {
            continue;
        }
        if (pipe_has_writer_in_process_fd_table(proc->fds, pipe_id)) {
            return true;
        }
    }
    return false;
}

static bool pipe_has_reader_in_process_fd_table(const struct process_fd* fds, int pipe_id) {
    for (int fd = 0; fd < PROCESS_MAX_FDS; ++fd) {
        if (fds[fd].kind == FD_PIPE_R && fds[fd].pipe_id == pipe_id) {
            return true;
        }
    }
    return false;
}

static bool pipe_has_reader(int pipe_id) {
    for (int fd = 0; fd < MAX_FDS; ++fd) {
        if (g_fds[fd].kind == FD_PIPE_R && g_fds[fd].pipe_id == pipe_id) {
            return true;
        }
    }
    for (int i = 0; i < MAX_PROCESSES; ++i) {
        struct process* proc = process_at(i);
        if (proc == current_process() || !process_holds_pipe_refs(proc)) {
            continue;
        }
        if (pipe_has_reader_in_process_fd_table(proc->fds, pipe_id)) {
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

static void release_process_fds(struct process* proc) {
    if (proc == NULL) {
        return;
    }

    int pipe_ids[PROCESS_MAX_FDS];
    size_t pipe_count = 0;
    for (int fd = 0; fd < PROCESS_MAX_FDS; ++fd) {
        if ((proc->fds[fd].kind == FD_PIPE_R || proc->fds[fd].kind == FD_PIPE_W) && proc->fds[fd].pipe_id >= 0) {
            int pipe_id = proc->fds[fd].pipe_id;
            bool seen = false;
            for (size_t i = 0; i < pipe_count; ++i) {
                if (pipe_ids[i] == pipe_id) {
                    seen = true;
                    break;
                }
            }
            if (!seen && pipe_count < ARRAY_LEN(pipe_ids)) {
                pipe_ids[pipe_count++] = pipe_id;
            }
        }
        memset(&proc->fds[fd], 0, sizeof(proc->fds[fd]));
        proc->fds[fd].pipe_id = -1;
    }

    for (size_t i = 0; i < pipe_count; ++i) {
        int pipe_id = pipe_ids[i];
        if (pipe_id >= 0 && pipe_id < MAX_PIPES && g_pipes[pipe_id].used && !pipe_is_referenced(pipe_id)) {
            memset(&g_pipes[pipe_id], 0, sizeof(g_pipes[pipe_id]));
        }
    }
}

static void close_cloexec_fds(void) {
    for (int fd = 0; fd < MAX_FDS; ++fd) {
        if (g_fds[fd].kind == FD_FREE) {
            continue;
        }
        if ((g_fds[fd].fd_flags & FD_CLOEXEC) != 0u) {
            (void)sys_close(fd);
        }
    }
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

static bool is_fb_path(const char* path) {
    return strcmp(path, "/dev/fb0") == 0;
}

static bool get_fb_info(struct console_framebuffer_info* info) {
    if (info == NULL) {
        return false;
    }
    return console_get_framebuffer_info(info);
}

static void fill_fb_fix_screeninfo(struct fb_fix_screeninfo* fix, const struct console_framebuffer_info* info) {
    memset(fix, 0, sizeof(*fix));
    strcpy(fix->id, "vibeosfb");
    fix->smem_start = (unsigned long)info->phys_addr;
    fix->smem_len = info->size;
    fix->type = FB_TYPE_PACKED_PIXELS;
    fix->visual = FB_VISUAL_TRUECOLOR;
    fix->line_length = info->pitch;
    fix->accel = FB_ACCEL_NONE;
}

static void fill_fb_var_screeninfo(struct fb_var_screeninfo* var, const struct console_framebuffer_info* info) {
    memset(var, 0, sizeof(*var));
    var->xres = info->width;
    var->yres = info->height;
    var->xres_virtual = info->width;
    var->yres_virtual = info->height;
    var->bits_per_pixel = info->bpp;
    var->red.offset = info->red_offset;
    var->red.length = info->red_length;
    var->green.offset = info->green_offset;
    var->green.length = info->green_length;
    var->blue.offset = info->blue_offset;
    var->blue.length = info->blue_length;
    var->transp.offset = info->transp_offset;
    var->transp.length = info->transp_length;
}

static void init_fb_cmap_defaults(void) {
    for (size_t i = 0; i < ARRAY_LEN(g_fb_cmap_red); ++i) {
        uint16_t value = (uint16_t)((i << 8) | i);
        g_fb_cmap_red[i] = value;
        g_fb_cmap_green[i] = value;
        g_fb_cmap_blue[i] = value;
        g_fb_cmap_transp[i] = 0u;
    }
}

static int fb_cmap_bounds_check(const struct fb_cmap* cmap) {
    if (cmap == NULL) {
        return err(EFAULT);
    }
    if (cmap->len == 0u) {
        return 0;
    }
    if (cmap->start >= ARRAY_LEN(g_fb_cmap_red) || cmap->len > ARRAY_LEN(g_fb_cmap_red) - cmap->start) {
        return err(EINVAL);
    }
    return 0;
}

static void fb_cmap_readback(const struct fb_cmap* cmap) {
    uint32_t start = cmap->start;
    for (uint32_t i = 0; i < cmap->len; ++i) {
        if (cmap->red != NULL) {
            cmap->red[i] = g_fb_cmap_red[start + i];
        }
        if (cmap->green != NULL) {
            cmap->green[i] = g_fb_cmap_green[start + i];
        }
        if (cmap->blue != NULL) {
            cmap->blue[i] = g_fb_cmap_blue[start + i];
        }
        if (cmap->transp != NULL) {
            cmap->transp[i] = g_fb_cmap_transp[start + i];
        }
    }
}

static void fb_cmap_update(const struct fb_cmap* cmap) {
    uint32_t start = cmap->start;
    for (uint32_t i = 0; i < cmap->len; ++i) {
        if (cmap->red != NULL) {
            g_fb_cmap_red[start + i] = cmap->red[i];
        }
        if (cmap->green != NULL) {
            g_fb_cmap_green[start + i] = cmap->green[i];
        }
        if (cmap->blue != NULL) {
            g_fb_cmap_blue[start + i] = cmap->blue[i];
        }
        if (cmap->transp != NULL) {
            g_fb_cmap_transp[start + i] = cmap->transp[i];
        }
    }
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
    return fs_path_has_child(dir);
}

static int path_mode_size(const char* path, uint32_t* mode_out, size_t* size_out, struct fs_entry* entry_out) {
    struct fs_entry e;

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

    if (is_fb_path(path)) {
        struct console_framebuffer_info fb;
        if (!get_fb_info(&fb)) {
            return err(ENOENT);
        }
        if (mode_out != NULL) {
            *mode_out = S_IFCHR | 0666u;
        }
        if (size_out != NULL) {
            *size_out = fb.size;
        }
        if (entry_out != NULL) {
            memset(entry_out, 0, sizeof(*entry_out));
            strncpy(entry_out->path, path, sizeof(entry_out->path));
            entry_out->mode = S_IFCHR | 0666u;
            entry_out->size = fb.size;
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

    if (fs_lookup(path, &e) == 0) {
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

static int child_index_of(char names[MAX_CHILDREN][64], size_t count, const char* name) {
    for (size_t i = 0; i < count; ++i) {
        if (strcmp(names[i], name) == 0) {
            return (int)i;
        }
    }
    return -1;
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

    count += fs_collect_children(dir, names + count, types + count, MAX_CHILDREN - count);

    if (strcmp(dir, "/dev") == 0) {
        const char* dev_nodes[] = {"tty", "console", "null", "fb0"};
        for (size_t i = 0; i < ARRAY_LEN(dev_nodes) && count < MAX_CHILDREN; ++i) {
            if (strcmp(dev_nodes[i], "fb0") == 0) {
                struct console_framebuffer_info fb;
                if (!get_fb_info(&fb)) {
                    continue;
                }
            }
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

    struct process* proc = current_process();
    if (proc == NULL) {
        return err(EFAULT);
    }

    for (size_t i = 0; i < out_len; ++i) {
        if (!vm_space_range_mapped(&proc->vm, (uint64_t)(uintptr_t)(user + i), 1)) {
            return err(EFAULT);
        }
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
        g_fds[fd].fd_flags = 0;
        g_fds[fd].offset = 0;
        g_fds[fd].pipe_id = -1;
        strncpy(g_fds[fd].path, path, sizeof(g_fds[fd].path));
        sync_current_process_runtime();
        return fd;
    }

    if (is_null_path(path)) {
        int fd = alloc_fd();
        if (fd < 0) {
            return fd;
        }
        g_fds[fd].kind = FD_NULL;
        g_fds[fd].flags = flags;
        g_fds[fd].fd_flags = 0;
        g_fds[fd].offset = 0;
        g_fds[fd].pipe_id = -1;
        strncpy(g_fds[fd].path, path, sizeof(g_fds[fd].path));
        sync_current_process_runtime();
        return fd;
    }

    if (is_fb_path(path)) {
        struct console_framebuffer_info fb;
        if (!get_fb_info(&fb)) {
            return err(ENOENT);
        }
        int fd = alloc_fd();
        if (fd < 0) {
            return fd;
        }
        g_fds[fd].kind = FD_FB;
        g_fds[fd].flags = flags;
        g_fds[fd].fd_flags = 0;
        g_fds[fd].offset = 0;
        g_fds[fd].pipe_id = -1;
        memset(&g_fds[fd].entry, 0, sizeof(g_fds[fd].entry));
        g_fds[fd].entry.mode = S_IFCHR | 0666u;
        g_fds[fd].entry.size = fb.size;
        strncpy(g_fds[fd].path, path, sizeof(g_fds[fd].path));
        sync_current_process_runtime();
        return fd;
    }

    struct fs_entry e;
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
            g_fds[fd].fd_flags = 0;
            g_fds[fd].offset = 0;
            g_fds[fd].pipe_id = -1;
            strncpy(g_fds[fd].path, "/dev/null", sizeof(g_fds[fd].path));
            sync_current_process_runtime();
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
    g_fds[fd].fd_flags = 0;
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
    sync_current_process_runtime();
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
    sync_current_process_runtime();
    return 0;
}

static int sys_read(int fd, void* buf, size_t count, struct syscall_frame* frame) {
    if (count == 0) {
        return 0;
    }
    if (fd < 0 || fd >= MAX_FDS || g_fds[fd].kind == FD_FREE) {
        return err(EBADF);
    }

    if (g_fds[fd].kind == FD_TTY) {
        service_keyboard_signal_for_tty();
        if (g_pending_keyboard_signal != 0) {
            return handle_pending_keyboard_signal(frame);
        }

        char* out = (char*)buf;
        size_t written = 0;
        bool nonblocking = fd_is_nonblocking(fd);
        while (written < count) {
            int c = -1;
            if (!nonblocking && written == 0) {
                for (;;) {
                    service_keyboard_signal_for_tty();
                    if (g_pending_keyboard_signal != 0) {
                        return handle_pending_keyboard_signal(frame);
                    }
                    c = input_poll_char();
                    if (c >= 0) {
                        break;
                    }
                    if (frame != NULL && has_other_runnable_process(current_process())) {
                        struct process* proc = current_process();
                        int sr = save_live_process(proc, frame);
                        if (sr != 0) {
                            return sr;
                        }
                        proc->state = PROCESS_BLOCKED;
                        proc->wait.reason = PROCESS_WAIT_TTY_READ;
                        proc->wait.fd = fd;
                        proc->wait.ptr0 = (uint64_t)(uintptr_t)buf;
                        proc->wait.ptr1 = count;
                        proc->wait.has_timeout = false;
                        return (int)schedule_away(frame);
                    }
                    __asm__ volatile("pause");
                }
            } else {
                service_keyboard_signal_for_tty();
                c = input_poll_char();
            }
            if (c < 0) {
                if (written == 0 && g_pending_keyboard_signal != 0) {
                    return handle_pending_keyboard_signal(frame);
                }
                if (written == 0 && nonblocking) {
                    return err(EAGAIN);
                }
                break;
            }
            c = tty_normalize_char(c);
            int tty_sig = tty_is_foreground_group() ? tty_signal_for_char(c) : 0;
            if (tty_sig != 0) {
                int sr = tty_deliver_signal(tty_sig, frame);
                if (written == 0) {
                    return sr;
                }
                break;
            }
            out[written++] = (char)c;
        }
        if (written == 0 && g_pending_keyboard_signal != 0) {
            return handle_pending_keyboard_signal(frame);
        }
        return (int)written;
    }

    if (g_fds[fd].kind == FD_NULL) {
        return 0;
    }

    if (g_fds[fd].kind == FD_FB) {
        struct console_framebuffer_info fb;
        if (!get_fb_info(&fb)) {
            return err(ENODEV);
        }
        size_t off = g_fds[fd].offset;
        if (off >= fb.size) {
            return 0;
        }
        size_t n = count;
        if (n > fb.size - off) {
            n = fb.size - off;
        }
        memcpy(buf, (const void*)(uintptr_t)(fb.phys_addr + off), n);
        g_fds[fd].offset += n;
        return (int)n;
    }

    if (g_fds[fd].kind == FD_PIPE_R) {
        int pipe_id = g_fds[fd].pipe_id;
        if (pipe_id < 0 || pipe_id >= MAX_PIPES || !g_pipes[pipe_id].used) {
            return 0;
        }

        struct pipe_state* p = &g_pipes[pipe_id];
        while (p->size == 0) {
            if (!pipe_has_writer(pipe_id)) {
                return 0;
            }
            if (fd_is_nonblocking(fd)) {
                return err(EAGAIN);
            }
            if (frame != NULL && has_other_runnable_process(current_process())) {
                struct process* proc = current_process();
                int sr = save_live_process(proc, frame);
                if (sr != 0) {
                    return sr;
                }
                proc->state = PROCESS_BLOCKED;
                proc->wait.reason = PROCESS_WAIT_PIPE_READ;
                proc->wait.fd = fd;
                proc->wait.aux0 = pipe_id;
                proc->wait.ptr0 = (uint64_t)(uintptr_t)buf;
                proc->wait.ptr1 = count;
                proc->wait.has_timeout = false;
                return (int)schedule_away(frame);
            }
            __asm__ volatile("pause");
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

    size_t size = g_fds[fd].entry.size;
    size_t off = g_fds[fd].offset;
    if (off >= size) {
        return 0;
    }

    int n = fs_read(&g_fds[fd].entry, off, buf, count);
    if (n > 0) {
        g_fds[fd].offset += (size_t)n;
    }
    return n;
}

static int sys_write(int fd, const void* buf, size_t count, struct syscall_frame* frame) {
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
        if (!pipe_has_reader(pipe_id)) {
            return err(EPIPE);
        }

        struct pipe_state* p = &g_pipes[pipe_id];
        size_t avail = PIPE_CAPACITY - p->size;
        while (avail == 0) {
            if (!pipe_has_reader(pipe_id)) {
                return err(EPIPE);
            }
            if (fd_is_nonblocking(fd)) {
                return err(EAGAIN);
            }
            if (frame != NULL && has_other_runnable_process(current_process())) {
                struct process* proc = current_process();
                int sr = save_live_process(proc, frame);
                if (sr != 0) {
                    return sr;
                }
                proc->state = PROCESS_BLOCKED;
                proc->wait.reason = PROCESS_WAIT_PIPE_WRITE;
                proc->wait.fd = fd;
                proc->wait.aux0 = pipe_id;
                proc->wait.ptr0 = (uint64_t)(uintptr_t)buf;
                proc->wait.ptr1 = count;
                proc->wait.has_timeout = false;
                return (int)schedule_away(frame);
            }
            __asm__ volatile("pause");
            avail = PIPE_CAPACITY - p->size;
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

    if (g_fds[fd].kind == FD_FB) {
        struct console_framebuffer_info fb;
        if (!get_fb_info(&fb)) {
            return err(ENODEV);
        }
        size_t off = g_fds[fd].offset;
        if (off >= fb.size) {
            return 0;
        }
        size_t n = count;
        if (n > fb.size - off) {
            n = fb.size - off;
        }
        memcpy((void*)(uintptr_t)(fb.phys_addr + off), buf, n);
        g_fds[fd].offset += n;
        return (int)n;
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

static int sys_writev(int fd, const struct linux_iovec* iov, size_t iovcnt, struct syscall_frame* frame) {
    if (iovcnt > 1024) {
        return err(EINVAL);
    }

    int total = 0;
    for (size_t i = 0; i < iovcnt; ++i) {
        int n = sys_write(fd, (const void*)(uintptr_t)iov[i].base, (size_t)iov[i].len, frame);
        if (n < 0) {
            return n;
        }
        total += n;
    }
    return total;
}

static int sys_readv(int fd, const struct linux_iovec* iov, size_t iovcnt, struct syscall_frame* frame) {
    if (iovcnt > 1024) {
        return err(EINVAL);
    }

    int total = 0;
    for (size_t i = 0; i < iovcnt; ++i) {
        int n = sys_read(fd, (void*)(uintptr_t)iov[i].base, (size_t)iov[i].len, frame);
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
        if (g_fds[fd].kind == FD_FB) {
            struct console_framebuffer_info fb;
            if (!get_fb_info(&fb)) {
                return err(ENODEV);
            }
            base = (int64_t)fb.size;
        } else {
            base = (int64_t)g_fds[fd].entry.size;
        }
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

    if (g_fds[fd].kind == FD_FB) {
        struct console_framebuffer_info fb;
        if (!get_fb_info(&fb)) {
            return err(ENODEV);
        }
        size_t off = (size_t)offset;
        if (off >= fb.size) {
            return 0;
        }
        size_t n = count;
        if (n > fb.size - off) {
            n = fb.size - off;
        }
        memcpy(buf, (const void*)(uintptr_t)(fb.phys_addr + off), n);
        return (int)n;
    }

    size_t size = g_fds[fd].entry.size;
    size_t off = (size_t)offset;
    if (off >= size) {
        return 0;
    }

    return fs_read(&g_fds[fd].entry, off, buf, count);
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
    uint8_t buffer[4096];

    while (written < total) {
        size_t chunk = total - written;
        if (chunk > sizeof(buffer)) {
            chunk = sizeof(buffer);
        }

        int rr = fs_read(&g_fds[in_fd].entry, (size_t)off + written, buffer, chunk);
        if (rr < 0) {
            return (written > 0) ? (int64_t)written : (int64_t)rr;
        }
        if (rr == 0) {
            break;
        }
        int w = sys_write(out_fd, buffer, (size_t)rr, NULL);
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

    if (g_fds[fd].kind == FD_FB) {
        struct console_framebuffer_info fb;
        if (!get_fb_info(&fb)) {
            return err(ENODEV);
        }

        if (req == FBIOGET_FSCREENINFO) {
            if (argp != NULL) {
                struct fb_fix_screeninfo fix;
                fill_fb_fix_screeninfo(&fix, &fb);
                memcpy(argp, &fix, sizeof(fix));
            }
            return 0;
        }

        if (req == FBIOGET_VSCREENINFO) {
            if (argp != NULL) {
                struct fb_var_screeninfo var;
                fill_fb_var_screeninfo(&var, &fb);
                memcpy(argp, &var, sizeof(var));
            }
            return 0;
        }

        if (req == FBIOGETCMAP) {
            if (argp == NULL) {
                return err(EFAULT);
            }
            struct fb_cmap cmap = *(const struct fb_cmap*)(uintptr_t)argp;
            int cr = fb_cmap_bounds_check(&cmap);
            if (cr != 0) {
                return cr;
            }
            fb_cmap_readback(&cmap);
            return 0;
        }

        if (req == FBIOPUTCMAP) {
            if (argp == NULL) {
                return err(EFAULT);
            }
            struct fb_cmap cmap = *(const struct fb_cmap*)(uintptr_t)argp;
            int cr = fb_cmap_bounds_check(&cmap);
            if (cr != 0) {
                return cr;
            }
            fb_cmap_update(&cmap);
            return 0;
        }

        if (req == FBIOPUT_VSCREENINFO) {
            if (argp == NULL) {
                return err(EFAULT);
            }

            struct fb_var_screeninfo requested;
            struct fb_var_screeninfo current;
            memcpy(&requested, argp, sizeof(requested));
            fill_fb_var_screeninfo(&current, &fb);
            if (requested.xres != current.xres || requested.yres != current.yres ||
                requested.xres_virtual != current.xres_virtual || requested.yres_virtual != current.yres_virtual ||
                requested.bits_per_pixel != current.bits_per_pixel || requested.red.offset != current.red.offset ||
                requested.red.length != current.red.length || requested.green.offset != current.green.offset ||
                requested.green.length != current.green.length || requested.blue.offset != current.blue.offset ||
                requested.blue.length != current.blue.length || requested.transp.offset != current.transp.offset ||
                requested.transp.length != current.transp.length) {
                return err(EINVAL);
            }

            memcpy(argp, &current, sizeof(current));
            return 0;
        }

        if (req == FBIOPAN_DISPLAY) {
            if (argp == NULL) {
                return err(EFAULT);
            }

            struct fb_var_screeninfo requested = *(const struct fb_var_screeninfo*)(uintptr_t)argp;
            struct fb_var_screeninfo current;
            fill_fb_var_screeninfo(&current, &fb);
            if (requested.xoffset != 0u || requested.yoffset != 0u) {
                return err(EINVAL);
            }
            memcpy(argp, &current, sizeof(current));
            return 0;
        }

        if (req == FBIOBLANK) {
            return 0;
        }

        return err(EINVAL);
    }

    if (g_fds[fd].kind != FD_TTY) {
        return err(ENOTTY);
    }

    if (req == TCGETS) {
        if (argp != NULL) {
            memcpy(argp, &g_tty_termios, sizeof(g_tty_termios));
        }
        return 0;
    }

    if (req == TIOCGPGRP) {
        if (argp != NULL) {
            *(int*)(uintptr_t)argp = g_terminal_fg_pgrp;
        }
        return 0;
    }

    if (req == TIOCSPGRP) {
        if (argp == NULL) {
            return err(EFAULT);
        }
        int pgid = *(const int*)(uintptr_t)argp;
        if (pgid <= 0) {
            return err(EINVAL);
        }
        g_terminal_fg_pgrp = pgid;
        return 0;
    }

    if (req == TIOCGWINSZ) {
        if (argp != NULL) {
            struct linux_winsize ws;
            struct console_framebuffer_info fb;
            ws.ws_row = 25;
            ws.ws_col = 80;
            if (get_fb_info(&fb)) {
                ws.ws_xpixel = (uint16_t)fb.width;
                ws.ws_ypixel = (uint16_t)fb.height;
            } else {
                ws.ws_xpixel = 0;
                ws.ws_ypixel = 0;
            }
            memcpy(argp, &ws, sizeof(ws));
        }
        return 0;
    }

    if (req == TCSETS || req == TCSETSW || req == TCSETSF) {
        if (argp != NULL) {
            memcpy(&g_tty_termios, argp, sizeof(g_tty_termios));
        }
        return 0;
    }

    if (req == FIONREAD) {
        if (argp != NULL) {
            *(int*)(uintptr_t)argp = input_char_ready() ? 1 : 0;
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
            g_fds[newfd].fd_flags = (cmd == 1030) ? FD_CLOEXEC : 0u;
            sync_current_process_runtime();
            return newfd;
        }
        case 1:  // F_GETFD
            return (int)(g_fds[fd].fd_flags & FD_CLOEXEC);
        case 3:  // F_GETFL
            return (int)g_fds[fd].flags;
        case 2:  // F_SETFD
            g_fds[fd].fd_flags = (uint32_t)arg & FD_CLOEXEC;
            sync_current_process_runtime();
            return 0;
        case 4:  // F_SETFL
            g_fds[fd].flags = (g_fds[fd].flags & ~0xFFFFu) | ((uint32_t)arg & 0xFFFFu);
            sync_current_process_runtime();
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
    if (newfd != oldfd) {
        g_fds[newfd].fd_flags = 0;
    }
    sync_current_process_runtime();
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
    g_fds[rfd].fd_flags = 0;
    g_fds[rfd].offset = 0;
    g_fds[rfd].pipe_id = pipe_id;
    strcpy(g_fds[rfd].path, "pipe:[r]");

    g_fds[wfd].kind = FD_PIPE_W;
    g_fds[wfd].flags = O_WRONLY;
    g_fds[wfd].fd_flags = 0;
    g_fds[wfd].offset = 0;
    g_fds[wfd].pipe_id = pipe_id;
    strcpy(g_fds[wfd].path, "pipe:[w]");

    pipefd[0] = rfd;
    pipefd[1] = wfd;
    sync_current_process_runtime();
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
    sync_current_process_runtime();
    return 0;
}

static uint16_t poll_revents_for_fd(const struct linux_pollfd* pfd) {
    int fd = pfd->fd;
    uint16_t events = (uint16_t)pfd->events;
    uint16_t revents = 0;

    if (fd < 0 || fd >= MAX_FDS || g_fds[fd].kind == FD_FREE) {
        return POLLNVAL;
    }

    switch (g_fds[fd].kind) {
        case FD_TTY:
            if ((events & (POLLIN | POLLPRI)) != 0u && tty_input_ready()) {
                revents |= POLLIN;
            }
            if ((events & POLLOUT) != 0u) {
                revents |= POLLOUT;
            }
            break;

        case FD_NULL:
            if ((events & POLLOUT) != 0u) {
                revents |= POLLOUT;
            }
            break;

        case FD_FB:
            if ((events & POLLIN) != 0u) {
                revents |= POLLIN;
            }
            if ((events & POLLOUT) != 0u) {
                revents |= POLLOUT;
            }
            break;

        case FD_PIPE_R:
        {
            int pipe_id = g_fds[fd].pipe_id;
            if (pipe_id >= 0 && pipe_id < MAX_PIPES && g_pipes[pipe_id].used) {
                if ((events & POLLIN) != 0u && g_pipes[pipe_id].size > 0) {
                    revents |= POLLIN;
                }
                if (g_pipes[pipe_id].size == 0 && !pipe_has_writer(pipe_id)) {
                    revents |= POLLHUP;
                }
            } else {
                revents |= POLLNVAL;
            }
            break;
        }

        case FD_PIPE_W:
        {
            int pipe_id = g_fds[fd].pipe_id;
            if (pipe_id >= 0 && pipe_id < MAX_PIPES && g_pipes[pipe_id].used) {
                if (!pipe_has_reader(pipe_id)) {
                    revents |= POLLERR;
                } else if ((events & POLLOUT) != 0u && g_pipes[pipe_id].size < PIPE_CAPACITY) {
                    revents |= POLLOUT;
                }
            } else {
                revents |= POLLNVAL;
            }
            break;
        }

        case FD_FILE:
        case FD_DIR:
            if ((events & POLLIN) != 0u) {
                revents |= POLLIN;
            }
            if ((events & POLLOUT) != 0u) {
                revents |= POLLOUT;
            }
            break;

        case FD_FREE:
            break;
    }

    return revents;
}

static bool fdset_has_fd(const uint8_t* set, int fd) {
    return (set[fd >> 3] & (uint8_t)(1u << (fd & 7))) != 0u;
}

static void fdset_add_fd(uint8_t* set, int fd) {
    set[fd >> 3] |= (uint8_t)(1u << (fd & 7));
}

static int select_scan(int nfds, const uint8_t* read_in, const uint8_t* write_in, const uint8_t* except_in, uint8_t* read_out,
                       uint8_t* write_out, uint8_t* except_out) {
    int ready = 0;

    for (int fd = 0; fd < nfds; ++fd) {
        bool want_read = read_in != NULL && fdset_has_fd(read_in, fd);
        bool want_write = write_in != NULL && fdset_has_fd(write_in, fd);
        bool want_except = except_in != NULL && fdset_has_fd(except_in, fd);

        if (!want_read && !want_write && !want_except) {
            continue;
        }
        if (fd < 0 || fd >= MAX_FDS || g_fds[fd].kind == FD_FREE) {
            return err(EBADF);
        }

        struct linux_pollfd pfd;
        pfd.fd = fd;
        pfd.events = 0;
        pfd.revents = 0;
        if (want_read) {
            pfd.events |= POLLIN | POLLPRI;
        }
        if (want_write) {
            pfd.events |= POLLOUT;
        }

        uint16_t revents = poll_revents_for_fd(&pfd);
        bool fd_ready = false;

        if (want_read && (revents & (POLLIN | POLLHUP | POLLERR)) != 0u) {
            fdset_add_fd(read_out, fd);
            fd_ready = true;
        }
        if (want_write && (revents & (POLLOUT | POLLERR)) != 0u) {
            fdset_add_fd(write_out, fd);
            fd_ready = true;
        }
        if (want_except && (revents & POLLPRI) != 0u) {
            fdset_add_fd(except_out, fd);
            fd_ready = true;
        }

        if (fd_ready) {
            ++ready;
        }
    }

    return ready;
}

static bool child_matches_wait_target(const struct process* parent, const struct process* child, int pid) {
    if (parent == NULL || child == NULL || child->ppid != parent->pid) {
        return false;
    }
    if (pid == -1) {
        return true;
    }
    if (pid == 0) {
        return child->pgid == parent->pgid;
    }
    if (pid < -1) {
        return child->pgid == -pid;
    }
    return child->pid == pid;
}

static bool zombie_matches_wait_target(const struct process* parent, const struct zombie_info* zombie, int pid) {
    if (parent == NULL || zombie == NULL || !zombie->valid || zombie->ppid != parent->pid) {
        return false;
    }
    if (pid == -1) {
        return true;
    }
    if (pid == 0) {
        return zombie->pgid == parent->pgid;
    }
    if (pid < -1) {
        return zombie->pgid == -pid;
    }
    return zombie->pid == pid;
}

static int find_zombie_for_wait(const struct process* parent, int pid) {
    for (int i = 0; i < MAX_ZOMBIES; ++i) {
        if (zombie_matches_wait_target(parent, &g_zombies[i], pid)) {
            return i;
        }
    }
    return -1;
}

static bool has_matching_child(const struct process* parent, int pid) {
    for (int i = 0; i < MAX_PROCESSES; ++i) {
        struct process* child = process_at(i);
        if (child == NULL || child->state == PROCESS_FREE) {
            continue;
        }
        if (!child_matches_wait_target(parent, child, pid)) {
            continue;
        }
        return true;
    }
    return false;
}

static int find_waitable_child_event(struct process* parent, int pid, int options, int* status_out) {
    for (int i = 0; i < MAX_PROCESSES; ++i) {
        struct process* child = process_at(i);
        if (child == NULL || child->state == PROCESS_FREE || child->state == PROCESS_ZOMBIE) {
            continue;
        }
        if (!child_matches_wait_target(parent, child, pid)) {
            continue;
        }
        if (!child->has_wait_event) {
            continue;
        }

        int status = child->last_wait_status;
        if ((status & 0xFFu) == 0x7Fu) {
            if ((options & WAIT_UNTRACED) == 0) {
                continue;
            }
        } else if (status == 0xFFFF) {
            if ((options & WAIT_CONTINUED) == 0) {
                continue;
            }
        }

        if (status_out != NULL) {
            *status_out = status;
        }
        return child->pid;
    }
    return 0;
}

static bool process_block_ready(const struct process* proc) {
    if (proc == NULL || proc->state != PROCESS_BLOCKED) {
        return false;
    }
    if (proc->pending_count > 0) {
        return true;
    }

    switch (proc->wait.reason) {
        case PROCESS_WAIT_TTY_READ:
            service_keyboard_signal_for_tty();
            return g_pending_keyboard_signal != 0 || input_char_ready();
        case PROCESS_WAIT_PIPE_READ:
        {
            int pipe_id = proc->wait.aux0;
            return pipe_id >= 0 && pipe_id < MAX_PIPES &&
                   ((!g_pipes[pipe_id].used) || g_pipes[pipe_id].size > 0 || !pipe_has_writer(pipe_id));
        }
        case PROCESS_WAIT_PIPE_WRITE:
        {
            int pipe_id = proc->wait.aux0;
            return pipe_id >= 0 && pipe_id < MAX_PIPES &&
                   ((!g_pipes[pipe_id].used) || !pipe_has_reader(pipe_id) || g_pipes[pipe_id].size < PIPE_CAPACITY);
        }
        case PROCESS_WAIT_WAIT4:
            return find_zombie_for_wait(proc, proc->wait.aux0) >= 0 ||
                   find_waitable_child_event((struct process*)proc, proc->wait.aux0, proc->wait.aux1, NULL) != 0;
        case PROCESS_WAIT_SELECT:
        {
            if (proc->wait.has_timeout && read_tsc() >= proc->wait.deadline_ns) {
                return true;
            }
            uint8_t read_out[SELECT_FDSET_BYTES];
            uint8_t write_out[SELECT_FDSET_BYTES];
            uint8_t except_out[SELECT_FDSET_BYTES];
            memset(read_out, 0, sizeof(read_out));
            memset(write_out, 0, sizeof(write_out));
            memset(except_out, 0, sizeof(except_out));
            return select_scan(proc->wait.nfds, proc->wait.ptr0 != 0 ? proc->wait.readfds : NULL,
                               proc->wait.ptr1 != 0 ? proc->wait.writefds : NULL,
                               proc->wait.ptr2 != 0 ? proc->wait.exceptfds : NULL, read_out, write_out, except_out) > 0;
        }
        case PROCESS_WAIT_NANOSLEEP:
            return read_tsc() >= proc->wait.deadline_ns;
        case PROCESS_WAIT_NONE:
        default:
            return false;
        }
}

static struct process* pick_ready_blocked_process(void) {
    for (int i = 0; i < MAX_PROCESSES; ++i) {
        g_scheduler_index = (g_scheduler_index + 1) % MAX_PROCESSES;
        struct process* proc = process_at(g_scheduler_index);
        if (proc == NULL || !proc->has_saved_context) {
            continue;
        }
        if (process_block_ready(proc)) {
            return proc;
        }
    }
    return NULL;
}

static bool has_schedulable_process_except(const struct process* current) {
    for (int i = 0; i < MAX_PROCESSES; ++i) {
        struct process* proc = process_at(i);
        if (proc == NULL || proc == current || proc->state == PROCESS_FREE || proc->state == PROCESS_ZOMBIE ||
            proc->state == PROCESS_STOPPED) {
            continue;
        }
        return true;
    }
    return false;
}

static void unblock_process(struct process* proc, int64_t retval) {
    proc->state = PROCESS_RUNNABLE;
    proc->saved_frame.rax = (uint64_t)retval;
    proc->wait.reason = PROCESS_WAIT_NONE;
}

static int try_complete_wait4(struct process* proc) {
    if (proc->pending_count > 0) {
        (void)process_take_pending_signal(proc);
        unblock_process(proc, err(EINTR));
        return 0;
    }

    int zombie_idx = find_zombie_for_wait(proc, proc->wait.aux0);
    if (zombie_idx >= 0) {
        if (proc->wait.ptr0 != 0) {
            *(int*)(uintptr_t)proc->wait.ptr0 = g_zombies[zombie_idx].exit_status;
        }
        int reaped = g_zombies[zombie_idx].pid;
        remove_zombie(zombie_idx);
        struct process* child = process_find(reaped);
        if (child != NULL && child->state == PROCESS_ZOMBIE) {
            process_free(child);
        }
        unblock_process(proc, reaped);
        return 0;
    }

    int status = 0;
    int pid = find_waitable_child_event(proc, proc->wait.aux0, proc->wait.aux1, &status);
    if (pid == 0) {
        return err(EAGAIN);
    }

    if (proc->wait.ptr0 != 0) {
        *(int*)(uintptr_t)proc->wait.ptr0 = status;
    }

    struct process* child = process_find(pid);
    if (child != NULL) {
        child->has_wait_event = false;
        if (child->state == PROCESS_ZOMBIE) {
            process_free(child);
        }
    }

    unblock_process(proc, pid);
    return 0;
}

static int try_complete_tty_read(struct process* proc) {
    service_keyboard_signal_for_tty();
    if (g_pending_keyboard_signal != 0) {
        int sig = take_keyboard_signal();
        (void)signal_process_group(g_terminal_fg_pgrp, sig);
    }
    if (proc->state == PROCESS_STOPPED || proc->state == PROCESS_ZOMBIE) {
        return 0;
    }
    if (proc->pending_count > 0) {
        (void)process_take_pending_signal(proc);
        unblock_process(proc, err(EINTR));
        return 0;
    }

    service_keyboard_signal_for_tty();
    if (g_pending_keyboard_signal != 0) {
        int sig = take_keyboard_signal();
        (void)sig;
        unblock_process(proc, err(EINTR));
        return 0;
    }

    char* out = (char*)(uintptr_t)proc->wait.ptr0;
    size_t count = (size_t)proc->wait.ptr1;
    size_t written = 0;
    while (written < count) {
        int c = input_poll_char();
        if (c < 0) {
            break;
        }
        c = tty_normalize_char(c);
        int tty_sig = tty_signal_for_char(c);
        if (tty_sig != 0) {
            (void)signal_process_group(g_terminal_fg_pgrp, tty_sig);
            unblock_process(proc, err(EINTR));
            return 0;
        }
        out[written++] = (char)c;
    }

    if (written == 0) {
        return err(EAGAIN);
    }

    unblock_process(proc, (int64_t)written);
    return 0;
}

static int try_complete_pipe_read(struct process* proc) {
    if (proc->pending_count > 0) {
        (void)process_take_pending_signal(proc);
        unblock_process(proc, err(EINTR));
        return 0;
    }

    int pipe_id = proc->wait.aux0;
    if (pipe_id < 0 || pipe_id >= MAX_PIPES || !g_pipes[pipe_id].used) {
        unblock_process(proc, 0);
        return 0;
    }

    struct pipe_state* p = &g_pipes[pipe_id];
    if (p->size == 0 && pipe_has_writer(pipe_id)) {
        return err(EAGAIN);
    }
    if (p->size == 0) {
        unblock_process(proc, 0);
        return 0;
    }

    void* buf = (void*)(uintptr_t)proc->wait.ptr0;
    size_t count = (size_t)proc->wait.ptr1;
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

    unblock_process(proc, (int64_t)n);
    return 0;
}

static int try_complete_pipe_write(struct process* proc) {
    if (proc->pending_count > 0) {
        (void)process_take_pending_signal(proc);
        unblock_process(proc, err(EINTR));
        return 0;
    }

    int pipe_id = proc->wait.aux0;
    if (pipe_id < 0 || pipe_id >= MAX_PIPES || !g_pipes[pipe_id].used) {
        unblock_process(proc, err(EBADF));
        return 0;
    }
    if (!pipe_has_reader(pipe_id)) {
        unblock_process(proc, err(EPIPE));
        return 0;
    }

    struct pipe_state* p = &g_pipes[pipe_id];
    size_t avail = PIPE_CAPACITY - p->size;
    if (avail == 0) {
        return err(EAGAIN);
    }

    const void* buf = (const void*)(uintptr_t)proc->wait.ptr0;
    size_t count = (size_t)proc->wait.ptr1;
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

    unblock_process(proc, (int64_t)n);
    return 0;
}

static int try_complete_select(struct process* proc) {
    service_keyboard_signal_for_tty();
    if (g_pending_keyboard_signal != 0) {
        int sig = take_keyboard_signal();
        (void)signal_process_group(g_terminal_fg_pgrp, sig);
    }
    if (proc->state == PROCESS_STOPPED || proc->state == PROCESS_ZOMBIE) {
        return 0;
    }
    if (proc->pending_count > 0) {
        (void)process_take_pending_signal(proc);
        unblock_process(proc, err(EINTR));
        return 0;
    }

    int nfds = proc->wait.nfds;
    size_t bytes = (size_t)((nfds + 7) >> 3);
    uint8_t read_out[SELECT_FDSET_BYTES];
    uint8_t write_out[SELECT_FDSET_BYTES];
    uint8_t except_out[SELECT_FDSET_BYTES];
    memset(read_out, 0, sizeof(read_out));
    memset(write_out, 0, sizeof(write_out));
    memset(except_out, 0, sizeof(except_out));

    if (proc->wait.has_timeout && read_tsc() >= proc->wait.deadline_ns) {
        if (proc->wait.ptr0 != 0 && bytes > 0) {
            memset((void*)(uintptr_t)proc->wait.ptr0, 0, bytes);
        }
        if (proc->wait.ptr1 != 0 && bytes > 0) {
            memset((void*)(uintptr_t)proc->wait.ptr1, 0, bytes);
        }
        if (proc->wait.ptr2 != 0 && bytes > 0) {
            memset((void*)(uintptr_t)proc->wait.ptr2, 0, bytes);
        }
        unblock_process(proc, 0);
        return 0;
    }

    int ready = select_scan(nfds, proc->wait.ptr0 != 0 ? proc->wait.readfds : NULL, proc->wait.ptr1 != 0 ? proc->wait.writefds : NULL,
                            proc->wait.ptr2 != 0 ? proc->wait.exceptfds : NULL, read_out, write_out, except_out);
    if (ready <= 0) {
        return ready == 0 ? err(EAGAIN) : ready;
    }

    if (proc->wait.ptr0 != 0 && bytes > 0) {
        memcpy((void*)(uintptr_t)proc->wait.ptr0, read_out, bytes);
    }
    if (proc->wait.ptr1 != 0 && bytes > 0) {
        memcpy((void*)(uintptr_t)proc->wait.ptr1, write_out, bytes);
    }
    if (proc->wait.ptr2 != 0 && bytes > 0) {
        memcpy((void*)(uintptr_t)proc->wait.ptr2, except_out, bytes);
    }

    unblock_process(proc, ready);
    return 0;
}

static int try_complete_nanosleep(struct process* proc) {
    if (proc->pending_count > 0) {
        (void)process_take_pending_signal(proc);
        unblock_process(proc, err(EINTR));
        return 0;
    }

    if (read_tsc() < proc->wait.deadline_ns) {
        return err(EAGAIN);
    }
    unblock_process(proc, 0);
    return 0;
}

static int complete_blocked_process(struct process* proc) {
    switch (proc->wait.reason) {
        case PROCESS_WAIT_TTY_READ:
            return try_complete_tty_read(proc);
        case PROCESS_WAIT_PIPE_READ:
            return try_complete_pipe_read(proc);
        case PROCESS_WAIT_PIPE_WRITE:
            return try_complete_pipe_write(proc);
        case PROCESS_WAIT_WAIT4:
            return try_complete_wait4(proc);
        case PROCESS_WAIT_SELECT:
            return try_complete_select(proc);
        case PROCESS_WAIT_NANOSLEEP:
            return try_complete_nanosleep(proc);
        case PROCESS_WAIT_NONE:
        default:
            return 0;
    }
}

static uint64_t schedule_away(struct syscall_frame* frame) {
    struct process* outgoing = current_process();

    for (;;) {
        struct process* next = pick_next_runnable_process(outgoing);
        if (next == NULL) {
            next = pick_ready_blocked_process();
        }

        if (next != NULL) {
            load_process_runtime(next);
            if (next->state == PROCESS_BLOCKED) {
                int cr = complete_blocked_process(next);
                if (cr != 0) {
                    if (next->state == PROCESS_BLOCKED) {
                        continue;
                    }
                }
                if (next->state != PROCESS_RUNNABLE) {
                    continue;
                }
                load_process_runtime(next);
            }
            next->state = PROCESS_RUNNING;
            restore_user_context(next, frame);
            return frame->rax;
        }

        __asm__ volatile("pause");
    }
}

static int sys_select_common(int nfds, void* readfds, void* writefds, void* exceptfds, bool has_timeout, int64_t timeout_sec,
                             int64_t timeout_nsec) {
    if (nfds < 0 || nfds > 1024) {
        return err(EINVAL);
    }

    size_t bytes = (size_t)((nfds + 7) >> 3);
    if (bytes > SELECT_FDSET_BYTES) {
        return err(EINVAL);
    }

    uint8_t read_in[SELECT_FDSET_BYTES];
    uint8_t write_in[SELECT_FDSET_BYTES];
    uint8_t except_in[SELECT_FDSET_BYTES];
    memset(read_in, 0, sizeof(read_in));
    memset(write_in, 0, sizeof(write_in));
    memset(except_in, 0, sizeof(except_in));

    if (readfds != NULL && bytes > 0) {
        memcpy(read_in, readfds, bytes);
    }
    if (writefds != NULL && bytes > 0) {
        memcpy(write_in, writefds, bytes);
    }
    if (exceptfds != NULL && bytes > 0) {
        memcpy(except_in, exceptfds, bytes);
    }

    uint64_t start = read_tsc();
    uint64_t budget = has_timeout ? timeout_to_tsc_cycles(timeout_sec, timeout_nsec) : UINT64_MAX;

    for (;;) {
        service_keyboard_signal_for_tty();
        if (g_pending_keyboard_signal != 0 && tty_is_foreground_group()) {
            return err(EINTR);
        }

        uint8_t read_out[SELECT_FDSET_BYTES];
        uint8_t write_out[SELECT_FDSET_BYTES];
        uint8_t except_out[SELECT_FDSET_BYTES];
        memset(read_out, 0, sizeof(read_out));
        memset(write_out, 0, sizeof(write_out));
        memset(except_out, 0, sizeof(except_out));

        int ready = select_scan(nfds, readfds != NULL ? read_in : NULL, writefds != NULL ? write_in : NULL,
                                exceptfds != NULL ? except_in : NULL, read_out, write_out, except_out);
        if (ready < 0) {
            return ready;
        }
        if (ready > 0) {
            if (readfds != NULL && bytes > 0) {
                memcpy(readfds, read_out, bytes);
            }
            if (writefds != NULL && bytes > 0) {
                memcpy(writefds, write_out, bytes);
            }
            if (exceptfds != NULL && bytes > 0) {
                memcpy(exceptfds, except_out, bytes);
            }
            return ready;
        }

        if (readfds != NULL && bytes > 0) {
            memset(readfds, 0, bytes);
        }
        if (writefds != NULL && bytes > 0) {
            memset(writefds, 0, bytes);
        }
        if (exceptfds != NULL && bytes > 0) {
            memset(exceptfds, 0, bytes);
        }

        if (has_timeout && timeout_expired(start, budget)) {
            return 0;
        }

        __asm__ volatile("pause");
    }
}

static int sys_poll(struct linux_pollfd* fds, size_t nfds, int timeout_ms) {
    if (nfds > 1024u) {
        return err(EINVAL);
    }

    for (;;) {
        service_keyboard_signal_for_tty();
        if (take_keyboard_signal() != 0) {
            return err(EINTR);
        }

        int ready = 0;
        for (size_t i = 0; i < nfds; ++i) {
            uint16_t revents = poll_revents_for_fd(&fds[i]);
            fds[i].revents = (int16_t)revents;
            if (revents != 0u) {
                ++ready;
            }
        }

        if (ready != 0) {
            return ready;
        }

        if (timeout_ms == 0) {
            return 0;
        }

        if (timeout_ms > 0) {
            --timeout_ms;
        }

        __asm__ volatile("pause");
    }
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

    struct fs_entry e;
    if (fs_lookup(path, &e) != 0) {
        return err(ENOENT);
    }
    if ((e.mode & S_IFMT) != S_IFLNK) {
        return err(EINVAL);
    }

    return fs_readlink(&e, out, bufsz);
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
    } else if (g_fds[fd].kind == FD_FB) {
        struct console_framebuffer_info fb;
        if (!get_fb_info(&fb)) {
            return err(ENODEV);
        }
        mode = S_IFCHR | 0666u;
        size = fb.size;
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

static int sys_select(int nfds, void* readfds, void* writefds, void* exceptfds, struct linux_timeval* timeout, struct syscall_frame* frame) {
    if (timeout == NULL) {
        size_t bytes = (size_t)((nfds + 7) >> 3);
        uint8_t read_in[SELECT_FDSET_BYTES];
        uint8_t write_in[SELECT_FDSET_BYTES];
        uint8_t except_in[SELECT_FDSET_BYTES];
        uint8_t read_out[SELECT_FDSET_BYTES];
        uint8_t write_out[SELECT_FDSET_BYTES];
        uint8_t except_out[SELECT_FDSET_BYTES];
        memset(read_in, 0, sizeof(read_in));
        memset(write_in, 0, sizeof(write_in));
        memset(except_in, 0, sizeof(except_in));
        memset(read_out, 0, sizeof(read_out));
        memset(write_out, 0, sizeof(write_out));
        memset(except_out, 0, sizeof(except_out));
        if (readfds != NULL && bytes > 0) {
            memcpy(read_in, readfds, bytes);
        }
        if (writefds != NULL && bytes > 0) {
            memcpy(write_in, writefds, bytes);
        }
        if (exceptfds != NULL && bytes > 0) {
            memcpy(except_in, exceptfds, bytes);
        }
        int ready = select_scan(nfds, readfds != NULL ? read_in : NULL, writefds != NULL ? write_in : NULL,
                                exceptfds != NULL ? except_in : NULL, read_out, write_out, except_out);
        if (ready != 0) {
            if (ready > 0) {
                if (readfds != NULL && bytes > 0) {
                    memcpy(readfds, read_out, bytes);
                }
                if (writefds != NULL && bytes > 0) {
                    memcpy(writefds, write_out, bytes);
                }
                if (exceptfds != NULL && bytes > 0) {
                    memcpy(exceptfds, except_out, bytes);
                }
            }
            return ready;
        }
        if (frame == NULL || !has_other_runnable_process(current_process())) {
            return sys_select_common(nfds, readfds, writefds, exceptfds, false, 0, 0);
        }

        struct process* proc = current_process();
        int sr = save_live_process(proc, frame);
        if (sr != 0) {
            return sr;
        }
        proc->state = PROCESS_BLOCKED;
        proc->wait.reason = PROCESS_WAIT_SELECT;
        proc->wait.nfds = nfds;
        proc->wait.ptr0 = (uint64_t)(uintptr_t)readfds;
        proc->wait.ptr1 = (uint64_t)(uintptr_t)writefds;
        proc->wait.ptr2 = (uint64_t)(uintptr_t)exceptfds;
        proc->wait.has_timeout = false;
        if (readfds != NULL && bytes > 0) {
            memcpy(proc->wait.readfds, readfds, bytes);
        }
        if (writefds != NULL && bytes > 0) {
            memcpy(proc->wait.writefds, writefds, bytes);
        }
        if (exceptfds != NULL && bytes > 0) {
            memcpy(proc->wait.exceptfds, exceptfds, bytes);
        }
        return (int)schedule_away(frame);
    }
    int r = sys_select_common(nfds, readfds, writefds, exceptfds, true, timeout->tv_sec, timeout->tv_usec * 1000);
    if (r != 0 || frame == NULL || !has_other_runnable_process(current_process())) {
        return r;
    }

    struct process* proc = current_process();
    int sr = save_live_process(proc, frame);
    if (sr != 0) {
        return sr;
    }
    proc->state = PROCESS_BLOCKED;
    proc->wait.reason = PROCESS_WAIT_SELECT;
    proc->wait.nfds = nfds;
    proc->wait.ptr0 = (uint64_t)(uintptr_t)readfds;
    proc->wait.ptr1 = (uint64_t)(uintptr_t)writefds;
    proc->wait.ptr2 = (uint64_t)(uintptr_t)exceptfds;
    proc->wait.has_timeout = true;
    proc->wait.deadline_ns = read_tsc() + timeout_to_tsc_cycles(timeout->tv_sec, timeout->tv_usec * 1000);
    size_t bytes = (size_t)((nfds + 7) >> 3);
    if (readfds != NULL && bytes > 0) {
        memcpy(proc->wait.readfds, readfds, bytes);
    }
    if (writefds != NULL && bytes > 0) {
        memcpy(proc->wait.writefds, writefds, bytes);
    }
    if (exceptfds != NULL && bytes > 0) {
        memcpy(proc->wait.exceptfds, exceptfds, bytes);
    }
    return (int)schedule_away(frame);
}

static int sys_pselect6(int nfds, void* readfds, void* writefds, void* exceptfds, const struct linux_timespec* timeout,
                        const struct linux_pselect_sigmask* sigmask_data, struct syscall_frame* frame) {
    (void)sigmask_data;
    if (timeout == NULL) {
        return sys_select(nfds, readfds, writefds, exceptfds, NULL, frame);
    }
    int r = sys_select_common(nfds, readfds, writefds, exceptfds, true, timeout->tv_sec, timeout->tv_nsec);
    if (r != 0 || frame == NULL || !has_other_runnable_process(current_process())) {
        return r;
    }

    struct process* proc = current_process();
    int sr = save_live_process(proc, frame);
    if (sr != 0) {
        return sr;
    }
    proc->state = PROCESS_BLOCKED;
    proc->wait.reason = PROCESS_WAIT_SELECT;
    proc->wait.nfds = nfds;
    proc->wait.ptr0 = (uint64_t)(uintptr_t)readfds;
    proc->wait.ptr1 = (uint64_t)(uintptr_t)writefds;
    proc->wait.ptr2 = (uint64_t)(uintptr_t)exceptfds;
    proc->wait.has_timeout = true;
    proc->wait.deadline_ns = read_tsc() + timeout_to_tsc_cycles(timeout->tv_sec, timeout->tv_nsec);
    size_t bytes = (size_t)((nfds + 7) >> 3);
    if (readfds != NULL && bytes > 0) {
        memcpy(proc->wait.readfds, readfds, bytes);
    }
    if (writefds != NULL && bytes > 0) {
        memcpy(proc->wait.writefds, writefds, bytes);
    }
    if (exceptfds != NULL && bytes > 0) {
        memcpy(proc->wait.exceptfds, exceptfds, bytes);
    }
    return (int)schedule_away(frame);
}

static int sys_nanosleep(const struct linux_timespec* req, struct linux_timespec* rem, struct syscall_frame* frame) {
    if (req == NULL) {
        return err(EFAULT);
    }
    if (req->tv_sec < 0 || req->tv_nsec < 0 || req->tv_nsec >= 1000000000ll) {
        return err(EINVAL);
    }

    uint64_t start = read_tsc();
    uint64_t budget = timeout_to_tsc_cycles(req->tv_sec, req->tv_nsec);
    while (!timeout_expired(start, budget)) {
        service_keyboard_signal_for_tty();
        if (g_pending_keyboard_signal != 0 && tty_is_foreground_group()) {
            if (rem != NULL) {
                rem->tv_sec = 0;
                rem->tv_nsec = 0;
            }
            return err(EINTR);
        }
        if (frame != NULL && has_other_runnable_process(current_process())) {
            struct process* proc = current_process();
            int sr = save_live_process(proc, frame);
            if (sr != 0) {
                return sr;
            }
            proc->state = PROCESS_BLOCKED;
            proc->wait.reason = PROCESS_WAIT_NANOSLEEP;
            proc->wait.has_timeout = true;
            proc->wait.deadline_ns = start + budget;
            return (int)schedule_away(frame);
        }
        __asm__ volatile("pause");
    }

    g_fake_time_ns += (uint64_t)req->tv_sec * 1000000000ull + (uint64_t)req->tv_nsec;
    if (rem != NULL) {
        rem->tv_sec = 0;
        rem->tv_nsec = 0;
    }
    return 0;
}

static int sys_umask(uint32_t mask) {
    uint32_t old = g_umask;
    g_umask = mask & 0777u;
    return (int)old;
}

static int sys_getrlimit(int resource, struct linux_rlimit* rlim) {
    (void)resource;
    if (rlim == NULL) {
        return err(EFAULT);
    }

    rlim->rlim_cur = RLIM_INFINITY;
    rlim->rlim_max = RLIM_INFINITY;
    return 0;
}

static int sys_prlimit64(int pid, int resource, const struct linux_rlimit* new_limit, struct linux_rlimit* old_limit) {
    (void)resource;
    if (pid != 0 && pid != g_current_pid) {
        return err(ESRCH);
    }
    if (old_limit != NULL) {
        old_limit->rlim_cur = RLIM_INFINITY;
        old_limit->rlim_max = RLIM_INFINITY;
    }
    if (new_limit != NULL) {
        return 0;
    }
    return 0;
}

static int sys_setpgid(int pid, int pgid) {
    if (pid == 0) {
        pid = g_current_pid;
    }
    if (pgid == 0) {
        pgid = pid;
    }
    if (pid <= 0 || pgid <= 0) {
        return err(EINVAL);
    }

    struct process* target = process_find(pid);
    if (target == NULL || target->state == PROCESS_ZOMBIE) {
        return err(ESRCH);
    }
    if (target->pid != g_current_pid && target->ppid != g_current_pid) {
        return err(EPERM);
    }

    target->pgid = pgid;
    if (target == current_process()) {
        g_current_pgid = pgid;
    }

    return 0;
}

static int sys_getpgrp(void) {
    return g_current_pgid;
}

static int sys_setsid(void) {
    if (g_current_pid == g_current_pgid) {
        return err(EPERM);
    }

    struct process* current = current_process();
    if (current == NULL) {
        return err(ESRCH);
    }

    g_current_sid = g_current_pid;
    g_current_pgid = g_current_pid;
    current->sid = g_current_sid;
    current->pgid = g_current_pgid;
    return g_current_sid;
}

static int sys_getpgid(int pid) {
    if (pid == 0) {
        pid = g_current_pid;
    }
    struct process* target = process_find(pid);
    if (target == NULL) {
        return err(ESRCH);
    }
    return target->pgid;
}

static int64_t sys_mmap(uint64_t addr, size_t len, uint64_t prot, uint64_t flags, int fd, uint64_t offset) {
    (void)prot;
    if (len == 0) {
        return err(EINVAL);
    }

    struct process* current = current_process();
    if (current == NULL) {
        return err(ENOMEM);
    }

    const uint64_t align = 0x1000ull;
    uint64_t span = ((uint64_t)len + align - 1u) & ~(align - 1u);
    bool anonymous = (flags & MAP_ANONYMOUS) != 0u;

    if ((offset & (align - 1u)) != 0u) {
        return err(EINVAL);
    }

    if (!anonymous && (flags & (MAP_SHARED | MAP_PRIVATE)) == 0u) {
        return err(EINVAL);
    }

    uint64_t base = 0;
    if (addr != 0 && (flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) != 0u) {
        base = addr & ~(align - 1u);
        if (base < 0x1000ull || base + span >= VM_USER_MMAP_LIMIT) {
            return err(ENOMEM);
        }
        if ((flags & MAP_FIXED_NOREPLACE) != 0u && vm_space_range_mapped(&current->vm, base, (size_t)span)) {
            return err(EEXIST);
        }
        if ((flags & MAP_FIXED) != 0u) {
            (void)vm_space_unmap(&current->vm, base, (size_t)span);
        }
    } else {
        base = (g_mmap_next + align - 1u) & ~(align - 1u);
        if (base + span >= VM_USER_MMAP_LIMIT) {
            return err(ENOMEM);
        }
        g_mmap_next = base + span;
    }

    if (!anonymous) {
        if (fd < 0 || fd >= MAX_FDS || g_fds[fd].kind == FD_FREE) {
            return err(EBADF);
        }

        if (g_fds[fd].kind == FD_FB) {
            struct console_framebuffer_info fb;
            uint64_t phys_base;
            if (!get_fb_info(&fb)) {
                return err(ENODEV);
            }
            if ((size_t)offset > fb.size) {
                return err(EINVAL);
            }
            if ((size_t)offset + len > fb.size) {
                return err(EINVAL);
            }
            phys_base = (fb.phys_addr + offset) & ~(align - 1u);
            if (vm_space_map_physical(&current->vm, base, phys_base, (size_t)span) != 0) {
                return err(ENOMEM);
            }
            return (int64_t)base;
        }

        if (g_fds[fd].kind != FD_FILE) {
            return err(EBADF);
        }

        if (vm_space_map_zero(&current->vm, base, (size_t)span) != 0) {
            return err(ENOMEM);
        }

        const struct fs_entry* entry = &g_fds[fd].entry;
        size_t file_off = (size_t)offset;
        if (file_off < entry->size) {
            size_t remain = entry->size - file_off;
            size_t copy_len = (len < remain) ? len : remain;
            uint8_t* file_data = kmalloc(copy_len);
            if (file_data == NULL) {
                (void)vm_space_unmap(&current->vm, base, (size_t)span);
                return err(ENOMEM);
            }
            int rr = fs_read(entry, file_off, file_data, copy_len);
            if (rr < 0) {
                kfree(file_data);
                (void)vm_space_unmap(&current->vm, base, (size_t)span);
                return rr;
            }
            int wr = vm_space_write(&current->vm, base, file_data, (size_t)rr);
            kfree(file_data);
            if (wr != 0) {
                (void)vm_space_unmap(&current->vm, base, (size_t)span);
                return err(ENOMEM);
            }
        }
    } else if (vm_space_map_zero(&current->vm, base, (size_t)span) != 0) {
        return err(ENOMEM);
    }

    return (int64_t)base;
}

static int sys_munmap(uint64_t addr, size_t len) {
    struct process* current = current_process();
    if (current == NULL) {
        return err(EINVAL);
    }
    if (len == 0) {
        return 0;
    }
    return vm_space_unmap(&current->vm, addr, len) == 0 ? 0 : err(EINVAL);
}

static int64_t sys_brk(uint64_t brk) {
    struct process* current = current_process();
    if (current == NULL) {
        return (int64_t)g_brk_current;
    }

    uint64_t old = g_brk_current;
    if (brk == 0) {
        return (int64_t)g_brk_current;
    }
    if (brk < VM_USER_BRK_BASE || brk >= VM_USER_MMAP_BASE) {
        return (int64_t)g_brk_current;
    }
    if (brk > old) {
        if (vm_space_map_zero(&current->vm, old, (size_t)(brk - old)) != 0) {
            return (int64_t)g_brk_current;
        }
    } else if (brk < old) {
        uint64_t release_start = (brk + VM_PAGE_SIZE - 1ull) & VM_PAGE_MASK;
        if (release_start < old) {
            (void)vm_space_unmap(&current->vm, release_start, (size_t)(old - release_start));
        }
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

static uint64_t exec_stack_push_bytes(uint64_t sp, const void* data, size_t len, struct process* proc) {
    sp -= len;
    (void)vm_space_write(&proc->vm, sp, data, len);
    return sp;
}

static uint64_t exec_stack_push_u64(uint64_t sp, uint64_t value, struct process* proc) {
    sp -= sizeof(uint64_t);
    (void)vm_space_write(&proc->vm, sp, &value, sizeof(value));
    return sp;
}

static uint64_t exec_stack_push_auxv(uint64_t sp, uint64_t type, uint64_t value, struct process* proc) {
    sp = exec_stack_push_u64(sp, value, proc);
    sp = exec_stack_push_u64(sp, type, proc);
    return sp;
}

static int copy_user_str_array(uint64_t user_ptr, char out[][EXEC_STR_MAX], size_t max_out, size_t* count_out) {
    *count_out = 0;
    if (user_ptr == 0) {
        return 0;
    }

    struct process* proc = current_process();
    if (proc == NULL) {
        return err(EFAULT);
    }

    const uint64_t* list = (const uint64_t*)(uintptr_t)user_ptr;
    for (size_t i = 0; i < max_out; ++i) {
        if (!vm_space_range_mapped(&proc->vm, user_ptr + i * sizeof(uint64_t), sizeof(uint64_t))) {
            return err(EFAULT);
        }
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

static int map_exec_segment(struct process* proc, uint64_t vaddr, size_t memsz, const void* src, size_t filesz) {
    if (proc == NULL) {
        return err(EINVAL);
    }
    if (vm_space_map_zero(&proc->vm, vaddr, memsz) != 0) {
        return err(ENOMEM);
    }
    if (filesz != 0 && vm_space_write(&proc->vm, vaddr, src, filesz) != 0) {
        return err(ENOMEM);
    }
    return 0;
}

static int load_exec_image(struct process* proc, const uint8_t* image, size_t image_size, uint64_t* entry_out, uint64_t* phdr_out,
                           uint64_t* phent_out,
                           uint64_t* phnum_out, uint64_t* image_start_out, uint64_t* image_end_out) {
    if (proc == NULL || image_size < sizeof(struct elf64_ehdr)) {
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
        if (ph[i].p_vaddr + ph[i].p_memsz >= VM_USER_ELF_LIMIT) {
            return err(ENOMEM);
        }

        const uint8_t* src = image + ph[i].p_offset;
        int mr = map_exec_segment(proc, ph[i].p_vaddr, (size_t)ph[i].p_memsz, src, (size_t)ph[i].p_filesz);
        if (mr != 0) {
            return mr;
        }

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
                            uint64_t phnum, uint64_t* stack_out, struct process* proc) {
    const char* platform = "x86_64";
    uint8_t at_random[16] = {
        0x12, 0x6E, 0xA7, 0x39, 0x55, 0xC8, 0x03, 0xF1, 0x88, 0x22, 0x74, 0xB5, 0xE1, 0x9C, 0x41, 0x0D,
    };

    if (proc == NULL || vm_space_map_zero(&proc->vm, VM_USER_STACK_BASE, VM_USER_STACK_SIZE) != 0) {
        return err(ENOMEM);
    }

    uint64_t sp = VM_USER_STACK_TOP;
    sp = exec_stack_push_bytes(sp, execfn, strlen(execfn) + 1u, proc);
    uint64_t execfn_ptr = sp;

    sp = exec_stack_push_bytes(sp, platform, strlen(platform) + 1u, proc);
    uint64_t platform_ptr = sp;

    sp = exec_stack_push_bytes(sp, at_random, sizeof(at_random), proc);
    uint64_t at_random_ptr = sp;

    for (int i = (int)envc - 1; i >= 0; --i) {
        sp = exec_stack_push_bytes(sp, envp[i], strlen(envp[i]) + 1u, proc);
        g_exec_env_ptrs[i] = sp;
    }
    for (int i = (int)argc - 1; i >= 0; --i) {
        sp = exec_stack_push_bytes(sp, argv[i], strlen(argv[i]) + 1u, proc);
        g_exec_argv_ptrs[i] = sp;
    }

    sp &= ~0x0Full;
    sp = exec_stack_push_auxv(sp, 0, 0, proc);
    sp = exec_stack_push_auxv(sp, 31, execfn_ptr, proc);
    sp = exec_stack_push_auxv(sp, 51, 2048, proc);
    sp = exec_stack_push_auxv(sp, 15, platform_ptr, proc);
    sp = exec_stack_push_auxv(sp, 25, at_random_ptr, proc);
    sp = exec_stack_push_auxv(sp, 16, 0, proc);
    sp = exec_stack_push_auxv(sp, 26, 0, proc);
    sp = exec_stack_push_auxv(sp, 33, 0, proc);
    sp = exec_stack_push_auxv(sp, 23, 0, proc);
    sp = exec_stack_push_auxv(sp, 17, 100, proc);
    sp = exec_stack_push_auxv(sp, 8, 0, proc);
    sp = exec_stack_push_auxv(sp, 7, 0, proc);
    sp = exec_stack_push_auxv(sp, 14, 0, proc);
    sp = exec_stack_push_auxv(sp, 13, 0, proc);
    sp = exec_stack_push_auxv(sp, 12, 0, proc);
    sp = exec_stack_push_auxv(sp, 11, 0, proc);
    sp = exec_stack_push_auxv(sp, 9, entry, proc);
    sp = exec_stack_push_auxv(sp, 6, 4096, proc);
    sp = exec_stack_push_auxv(sp, 5, phnum, proc);
    sp = exec_stack_push_auxv(sp, 4, phent, proc);
    sp = exec_stack_push_auxv(sp, 3, phdr, proc);

    sp = exec_stack_push_u64(sp, 0, proc);
    for (int i = (int)envc - 1; i >= 0; --i) {
        sp = exec_stack_push_u64(sp, g_exec_env_ptrs[i], proc);
    }

    sp = exec_stack_push_u64(sp, 0, proc);
    for (int i = (int)argc - 1; i >= 0; --i) {
        sp = exec_stack_push_u64(sp, g_exec_argv_ptrs[i], proc);
    }
    sp = exec_stack_push_u64(sp, argc, proc);

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

    struct fs_entry image_entry;
    if (fs_lookup(resolved_path, &image_entry) != 0 || (image_entry.mode & S_IFMT) != S_IFREG) {
        return err(ENOENT);
    }

    uint8_t* image = kmalloc(image_entry.size);
    if (image == NULL) {
        return err(ENOMEM);
    }
    int read_result = fs_read(&image_entry, 0, image, image_entry.size);
    if (read_result < 0 || (size_t)read_result != image_entry.size) {
        kfree(image);
        return (read_result < 0) ? read_result : err(EINVAL);
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

    struct process* current = current_process();
    if (current == NULL) {
        kfree(image);
        return err(ENOMEM);
    }

    vm_space_reset_user(&current->vm);

    uint64_t entry = 0;
    uint64_t phdr = 0;
    uint64_t phent = 0;
    uint64_t phnum = 0;
    uint64_t image_start = 0;
    uint64_t image_end = 0;
    int lr = load_exec_image(current, image, image_entry.size, &entry, &phdr, &phent, &phnum, &image_start, &image_end);
    if (lr != 0) {
        kfree(image);
        return lr;
    }
    kfree(image);

    g_brk_current = VM_USER_BRK_BASE;
    g_mmap_next = VM_USER_MMAP_BASE;
    g_tid_address = 0;
    write_fs_base_current(0);
    userland_set_image_span(image_start, image_end);

    current->tid_address = 0;
    current->fs_base = 0;
    current->image_start = image_start;
    current->image_end = image_end;
    current->brk_current = g_brk_current;
    current->mmap_next = g_mmap_next;

    uint64_t user_stack = 0;
    int sr = build_exec_stack(abs_path, g_exec_argv_scratch, argc, g_exec_env_scratch, envc, entry, phdr, phent, phnum, &user_stack,
                              current);
    if (sr != 0) {
        return sr;
    }

    close_cloexec_fds();
    sync_current_process_runtime();

    memset(frame, 0, sizeof(*frame));
    uint64_t* raw = (uint64_t*)(void*)frame;
    raw[IRET_SLOT_RIP] = entry;
    raw[IRET_SLOT_RSP] = user_stack;
    return 0;
}

static int sys_wait4(int pid, int* status, int options, struct syscall_frame* frame) {
    if ((options & ~(WAIT_NOHANG | WAIT_UNTRACED | WAIT_CONTINUED)) != 0) {
        return err(EINVAL);
    }
    struct process* current = current_process();
    if (current == NULL) {
        return err(ECHILD);
    }

    if (!has_matching_child(current, pid) && find_zombie_for_wait(current, pid) < 0) {
        return err(ECHILD);
    }

    current->wait.reason = PROCESS_WAIT_WAIT4;
    current->wait.aux0 = pid;
    current->wait.aux1 = options;
    current->wait.ptr0 = (uint64_t)(uintptr_t)status;
    current->wait.has_timeout = false;
    int immediate = try_complete_wait4(current);
    if (immediate == 0 && current->state == PROCESS_RUNNABLE) {
        current->state = PROCESS_RUNNING;
        return (int)current->saved_frame.rax;
    }
    current->wait.reason = PROCESS_WAIT_NONE;

    if ((options & WAIT_NOHANG) != 0) {
        return 0;
    }

    if (frame != NULL && has_other_runnable_process(current)) {
        int sr = save_live_process(current, frame);
        if (sr != 0) {
            return sr;
        }
        current->state = PROCESS_BLOCKED;
        current->wait.reason = PROCESS_WAIT_WAIT4;
        current->wait.aux0 = pid;
        current->wait.aux1 = options;
        current->wait.ptr0 = (uint64_t)(uintptr_t)status;
        current->wait.has_timeout = false;
        return (int)schedule_away(frame);
    }

    return err(EAGAIN);
}

static int sys_rt_sigaction(int sig, const void* act, void* oldact, size_t sigsetsize) {
    if (sig < 1 || sig >= (int)NSIG) {
        return err(EINVAL);
    }
    if (sigsetsize != sizeof(uint64_t)) {
        return err(EINVAL);
    }
    if (act == NULL && oldact == NULL) {
        return 0;
    }

    struct sigaction_data* current = &g_sig_actions[sig];

    if (oldact != NULL) {
        struct linux_sigaction* old = (struct linux_sigaction*)oldact;
        old->handler = current->handler;
        old->flags = current->flags;
        old->restorer = current->restorer;
        old->mask = current->mask;
    }

    if (act != NULL) {
        const struct linux_sigaction* newact = (const struct linux_sigaction*)act;
        current->handler = newact->handler;
        current->flags = newact->flags;
        current->restorer = newact->restorer;
        current->mask = newact->mask;
    }

    return 0;
}

static int sys_rt_sigprocmask(int how, const uint64_t* set, uint64_t* oldset, size_t sigsetsize) {
    if (sigsetsize != sizeof(uint64_t)) {
        return err(EINVAL);
    }
    if (oldset != NULL) {
        *oldset = g_sig_mask;
    }

    if (set != NULL) {
        uint64_t newmask = *set;
        switch (how) {
            case SIG_BLOCK:
                g_sig_mask |= newmask;
                break;
            case SIG_UNBLOCK:
                g_sig_mask &= ~newmask;
                break;
            case SIG_SETMASK:
                g_sig_mask = newmask;
                break;
            default:
                return err(EINVAL);
        }
        g_sig_mask &= ~((1ull << SIGKILL) | (1ull << SIGSTOP));
    }

    return 0;
}

static void queue_signal_for_process(struct process* proc, int sig) {
    if (proc == NULL || sig <= 0 || sig >= (int)NSIG) {
        return;
    }

    if (proc == current_process()) {
        if (g_pending_signal_count >= MAX_PENDING_SIGNALS) {
            return;
        }
        for (int i = 0; i < g_pending_signal_count; ++i) {
            if (g_pending_signals[i] == sig) {
                return;
            }
        }
        g_pending_signals[g_pending_signal_count++] = sig;
        return;
    }

    process_queue_signal(proc, sig);
}

static void note_child_status_change(struct process* proc, int status) {
    if (proc == NULL) {
        return;
    }

    proc->last_wait_status = status;
    proc->has_wait_event = true;

    struct process* parent = process_find(proc->ppid);
    if (parent != NULL) {
        queue_signal_for_process(parent, SIGCHLD);
    }
}

static void terminate_process(struct process* proc, int exit_code, int wait_status) {
    if (proc == NULL || proc->state == PROCESS_ZOMBIE || proc->state == PROCESS_FREE) {
        return;
    }

    release_process_fds(proc);
    proc->exit_code = exit_code;
    proc->exit_status = wait_status;
    proc->state = PROCESS_ZOMBIE;
    add_zombie(proc->pid, proc->ppid, proc->pgid, exit_code, wait_status);
    note_child_status_change(proc, wait_status);
}

static void stop_process(struct process* proc, int sig) {
    if (proc == NULL || proc->state == PROCESS_ZOMBIE || proc->state == PROCESS_STOPPED || proc->state == PROCESS_FREE) {
        return;
    }
    proc->state = PROCESS_STOPPED;
    proc->stop_signal = sig;
    note_child_status_change(proc, 0x7Fu | (sig << 8));
}

static void continue_process(struct process* proc) {
    if (proc == NULL || proc->state != PROCESS_STOPPED) {
        return;
    }
    proc->state = PROCESS_RUNNABLE;
    proc->saved_frame.rax = (uint64_t)err(EINTR);
    proc->wait.reason = PROCESS_WAIT_NONE;
    note_child_status_change(proc, 0xFFFF);
}

static int signal_process(struct process* proc, int sig) {
    if (proc == NULL) {
        return err(ESRCH);
    }
    if (sig == 0) {
        return 0;
    }

    /* In VibeOS, PID 1 is the userspace bootstrap process. Treat the
       traditional BusyBox halt/poweroff/reboot signals as kernel power
       controls regardless of that process's own signal dispositions. */
    if (proc->pid == 1) {
        switch (sig) {
            case SIGUSR1:
                power_halt();
            case SIGUSR2:
                power_shutdown();
            case SIGTERM:
                power_reboot();
            default:
                break;
        }
    }

    struct sigaction_data* action = &proc->sig_actions[sig];
    if (action->handler == SIGNAL_HANDLER_IGN) {
        return 0;
    }
    if (action->handler != SIGNAL_HANDLER_DFL) {
        queue_signal_for_process(proc, sig);
        return 0;
    }

    switch (sig) {
        case SIGSTOP:
        case SIGTSTP:
        case SIGTTIN:
        case SIGTTOU:
            stop_process(proc, sig);
            return 0;
        case SIGCONT:
            continue_process(proc);
            return 0;
        case SIGKILL:
            terminate_process(proc, 128 + sig, sig & 0x7F);
            return 0;
        case SIGINT:
        case SIGTERM:
        case SIGQUIT:
        case SIGABRT:
        case SIGPIPE:
            terminate_process(proc, 128 + sig, sig & 0x7F);
            return 0;
        default:
            queue_signal_for_process(proc, sig);
            return 0;
    }
}

static int signal_process_group(int pgid, int sig) {
    int delivered = 0;
    for (int i = 0; i < MAX_PROCESSES; ++i) {
        struct process* proc = process_at(i);
        if (proc == NULL || proc->state == PROCESS_FREE || proc->pgid != pgid) {
            continue;
        }
        int r = signal_process(proc, sig);
        if (r == 0) {
            delivered++;
        }
    }
    return delivered > 0 ? 0 : err(ESRCH);
}

static int sys_kill(int pid, int sig) {
    if (sig < 0 || sig >= (int)NSIG) {
        return err(EINVAL);
    }

    if (pid == 0) {
        pid = -g_current_pgid;
    }

    if (pid < -1) {
        return signal_process_group(-pid, sig);
    }

    if (pid == -1) {
        return err(ENOSYS);
    }
    return signal_process(process_find(pid), sig);
}

static void add_zombie(int pid, int ppid, int pgid, int exit_code, int exit_status) {
    for (int i = 0; i < MAX_ZOMBIES; ++i) {
        if (!g_zombies[i].valid) {
            g_zombies[i].valid = true;
            g_zombies[i].pid = pid;
            g_zombies[i].ppid = ppid;
            g_zombies[i].pgid = pgid;
            g_zombies[i].exit_code = exit_code;
            g_zombies[i].exit_status = exit_status;
            g_zombie_count++;
            return;
        }
    }
}

static void remove_zombie(int idx) {
    if (idx >= 0 && idx < MAX_ZOMBIES && g_zombies[idx].valid) {
        g_zombies[idx].valid = false;
        g_zombie_count--;
    }
}

static int sys_set_tid_address(uint64_t tidptr) {
    g_tid_address = tidptr;
    struct process* current = current_process();
    if (current != NULL) {
        current->tid_address = tidptr;
    }
    return g_current_pid;
}

__attribute__((noreturn)) static void do_shutdown(void) {
    power_shutdown();
}

__attribute__((noreturn)) static void do_halt(void) {
    power_halt();
}

__attribute__((noreturn)) static void do_reboot(void) {
    power_reboot();
}

static int sys_reboot(int magic1, int magic2, uint64_t cmd) {
    if (magic1 != (int)0xfee1dead || magic2 != 672274793) {
        return err(EINVAL);
    }
    switch (cmd) {
        case LINUX_REBOOT_CMD_POWER_OFF:
            do_shutdown();
        case LINUX_REBOOT_CMD_HALT:
            do_halt();
        case LINUX_REBOOT_CMD_RESTART:
        case LINUX_REBOOT_CMD_RESTART2:
            do_reboot();
        default:
            return err(EINVAL);
    }
}

static int sys_fork_like(struct syscall_frame* frame, uint64_t clone_flags, uint64_t child_stack, uint64_t child_tid_ptr, uint64_t tls,
                         bool from_clone) {
    if (from_clone) {
        uint64_t allowed = CLONE_SIGNAL_MASK | CLONE_VM | CLONE_VFORK | CLONE_SETTLS | CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID;
        if ((clone_flags & ~allowed) != 0ull) {
            return err(EINVAL);
        }
        if ((clone_flags & CLONE_SIGNAL_MASK) != SIGCHLD) {
            return err(EINVAL);
        }
        if (child_stack != 0 && (child_stack < 0x1000ull || child_stack >= VM_USER_MMAP_LIMIT)) {
            return err(EINVAL);
        }
        if ((clone_flags & (CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID)) != 0ull && child_tid_ptr == 0) {
            return err(EINVAL);
        }
    }

    struct process* current = current_process();
    if (current == NULL) {
        return err(EAGAIN);
    }

    int sr = save_live_process(current, frame);
    if (sr != 0) {
        return sr;
    }

    struct process* child = process_alloc();
    if (child == NULL) {
        return err(EAGAIN);
    }

    child->ppid = current->pid;
    child->pgid = current->pgid;
    child->sid = current->sid;
    child->state = PROCESS_RUNNABLE;
    child->is_child = true;
    child->image_start = current->image_start;
    child->image_end = current->image_end;
    child->brk_current = current->brk_current;
    child->mmap_next = current->mmap_next;
    child->umask = current->umask;
    child->fs_base = ((from_clone && (clone_flags & CLONE_SETTLS) != 0ull) ? tls : current->fs_base);
    child->tid_address = ((from_clone && (clone_flags & CLONE_CHILD_CLEARTID)) != 0ull) ? child_tid_ptr : current->tid_address;
    child->sig_mask = current->sig_mask;
    child->pending_count = 0;
    child->has_wait_event = false;
    child->stop_signal = 0;
    child->exit_code = 0;
    child->exit_status = 0;

    memcpy(child->fds, current->fds, sizeof(child->fds));
    memcpy(child->cwd, current->cwd, sizeof(child->cwd));
    memcpy(child->sig_actions, current->sig_actions, sizeof(child->sig_actions));
    memset(child->pending_signals, 0, sizeof(child->pending_signals));

    vm_space_destroy(&child->vm);
    if (vm_space_clone(&child->vm, &current->vm) != 0) {
        process_free(child);
        return err(ENOMEM);
    }

    child->saved_frame = current->saved_frame;
    memcpy(child->saved_iret, current->saved_iret, sizeof(child->saved_iret));
    child->saved_frame.rax = 0;
    if (from_clone && child_stack != 0) {
        child->saved_iret[3] = child_stack;
    }
    child->has_saved_context = true;
    child->wait.reason = PROCESS_WAIT_NONE;

    current->saved_frame.rax = (uint64_t)child->pid;
    if (from_clone && (clone_flags & CLONE_CHILD_SETTID) != 0ull) {
        *(uint32_t*)(uintptr_t)child_tid_ptr = (uint32_t)child->pid;
    }

    return child->pid;
}

static uint64_t sys_exit_common(struct syscall_frame* frame, uint64_t code) {
    if (g_tid_address != 0) {
        *(uint32_t*)(uintptr_t)g_tid_address = 0;
    }

    struct process* current = current_process();
    if (current == NULL) {
        leave_user_mode(code);
    }

    terminate_process(current, (int)(code & 0xFFu), ((int)(code & 0xFFu)) << 8);

    if (!has_schedulable_process_except(current)) {
        leave_user_mode(code);
    }

    return schedule_away(frame);
}

void syscall_init(void) {
    process_init();
    memset(g_fds, 0, sizeof(g_fds));
    memset(g_zombies, 0, sizeof(g_zombies));
    memset(g_sig_actions, 0, sizeof(g_sig_actions));
    memset(g_pending_signals, 0, sizeof(g_pending_signals));

    for (int i = 0; i < 3; ++i) {
        g_fds[i].kind = FD_TTY;
        g_fds[i].flags = O_RDWR;
        g_fds[i].offset = 0;
        g_fds[i].pipe_id = -1;
        strcpy(g_fds[i].path, "/dev/tty");
    }

    strcpy(g_cwd, "/");
    g_brk_current = VM_USER_BRK_BASE;
    g_mmap_next = VM_USER_MMAP_BASE;
    g_current_pid = 1;
    g_current_ppid = 0;
    g_current_pgid = 1;
    g_current_sid = 1;
    g_pending_keyboard_signal = 0;
    g_tid_address = 0;
    g_umask = 022u;
    g_terminal_fg_pgrp = 1;
    g_zombie_count = 0;
    g_pending_signal_count = 0;
    g_sig_mask = 0;
    memset(g_pipes, 0, sizeof(g_pipes));
    init_fb_cmap_defaults();
    init_default_tty_termios();

    struct process* init_proc = current_process();
    if (init_proc != NULL) {
        memcpy(init_proc->fds, g_fds, sizeof(g_fds));
        memcpy(init_proc->cwd, g_cwd, sizeof(g_cwd));
        init_proc->pgid = 1;
        init_proc->sid = 1;
        init_proc->brk_current = g_brk_current;
        init_proc->mmap_next = g_mmap_next;
        init_proc->umask = g_umask;
        vm_space_activate(&init_proc->vm);
    }

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

    switch (nr) {
        case 0:
        {
            int r = sys_read((int)a0, (void*)(uintptr_t)a1, (size_t)a2, frame);
            return (uint64_t)r;
        }
        case 1:
            return (uint64_t)sys_write((int)a0, (const void*)(uintptr_t)a1, (size_t)a2, frame);
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
        case 7:
            return (uint64_t)sys_poll((struct linux_pollfd*)(uintptr_t)a0, (size_t)a1, (int)(int64_t)a2);
        case 8:
            return (uint64_t)sys_lseek((int)a0, (int64_t)a1, (int)a2);
        case 9:
            return (uint64_t)sys_mmap(a0, (size_t)a1, a2, a3, (int)a4, a5);
        case 10:
            return 0;
        case 11:
            return (uint64_t)sys_munmap(a0, (size_t)a1);
        case 12:
            return (uint64_t)sys_brk(a0);
        case 13:
            return (uint64_t)sys_rt_sigaction((int)a0, (const void*)(uintptr_t)a1, (void*)(uintptr_t)a2, (size_t)a3);
        case 14:
            return (uint64_t)sys_rt_sigprocmask((int)a0, (const uint64_t*)(uintptr_t)a1, (uint64_t*)(uintptr_t)a2, (size_t)a3);
        case 16:
            return (uint64_t)sys_ioctl((int)a0, a1, (void*)(uintptr_t)a2);
        case 17:
            return (uint64_t)sys_pread64((int)a0, (void*)(uintptr_t)a1, (size_t)a2, (int64_t)a3);
        case 19:
        {
            int r = sys_readv((int)a0, (const struct linux_iovec*)(uintptr_t)a1, (size_t)a2, frame);
            return (uint64_t)r;
        }
        case 20:
            return (uint64_t)sys_writev((int)a0, (const struct linux_iovec*)(uintptr_t)a1, (size_t)a2, frame);
        case 21:
            return (uint64_t)sys_access_like(AT_FDCWD, (const char*)(uintptr_t)a0);
        case 22:
            return (uint64_t)sys_pipe2((int*)(uintptr_t)a0, 0);
        case 23:
            return (uint64_t)sys_select((int)a0, (void*)(uintptr_t)a1, (void*)(uintptr_t)a2, (void*)(uintptr_t)a3,
                                        (struct linux_timeval*)(uintptr_t)a4, frame);
        case 28:
            return 0;
        case 32:
            return (uint64_t)sys_dup_common((int)a0, 0, false);
        case 33:
            return (uint64_t)sys_dup_common((int)a0, (int)a1, true);
        case 35:
            return (uint64_t)sys_nanosleep((const struct linux_timespec*)(uintptr_t)a0, (struct linux_timespec*)(uintptr_t)a1, frame);
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
            return (uint64_t)sys_wait4((int)a0, (int*)(uintptr_t)a1, (int)a2, frame);
        case 62:
        {
            int r = sys_kill((int)a0, (int)a1);
            struct process* current = current_process();
            if (current != NULL && (current->state == PROCESS_STOPPED || current->state == PROCESS_ZOMBIE)) {
                int sr = save_live_process(current, frame);
                if (sr != 0) {
                    return (uint64_t)sr;
                }
                return schedule_away(frame);
            }
            return (uint64_t)r;
        }
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
        case 95:
            return (uint64_t)sys_umask((uint32_t)a0);
        case 97:
            return (uint64_t)sys_getrlimit((int)a0, (struct linux_rlimit*)(uintptr_t)a1);
        case 102:
        case 104:
        case 107:
        case 108:
            return 0;
        case 109:
            return (uint64_t)sys_setpgid((int)a0, (int)a1);
        case 110:
            return (uint64_t)g_current_ppid;
        case 111:
            return (uint64_t)sys_getpgrp();
        case 112:
            return (uint64_t)sys_setsid();
        case 121:
            return (uint64_t)sys_getpgid((int)a0);
        case 131:
            return 0;
        case 157:
            return 0;
        case 158:
            return (uint64_t)sys_arch_prctl(a0, a1);
        case 169:
            return (uint64_t)sys_reboot((int)a0, (int)a1, a2);
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
        case 270:
            return (uint64_t)sys_pselect6((int)a0, (void*)(uintptr_t)a1, (void*)(uintptr_t)a2, (void*)(uintptr_t)a3,
                                          (const struct linux_timespec*)(uintptr_t)a4,
                                          (const struct linux_pselect_sigmask*)(uintptr_t)a5, frame);
        case 273:
            return 0;
        case 292:
            return (uint64_t)sys_dup_common((int)a0, (int)a1, true);
        case 293:
            return (uint64_t)sys_pipe2((int*)(uintptr_t)a0, (uint32_t)a1);
        case 302:
            return (uint64_t)sys_prlimit64((int)a0, (int)a1, (const struct linux_rlimit*)(uintptr_t)a2,
                                           (struct linux_rlimit*)(uintptr_t)a3);
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
