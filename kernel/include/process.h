#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "initramfs.h"
#include "syscall.h"

#define MAX_PROCESSES 256
#define MAX_SIGNALS 64
#define MAX_PENDING_SIGNALS 32
#define PROCESS_MAX_FDS 64
#define PROCESS_SELECT_FDSET_BYTES 128

#define SIGNAL_HANDLER_DFL ((void*)0)
#define SIGNAL_HANDLER_IGN ((void*)1)

#define FORK_IMAGE_SNAPSHOT_MAX (16u * 1024u * 1024u)
#define FORK_STACK_SNAPSHOT_MAX (8u * 1024u * 1024u)
#define FORK_BRK_SNAPSHOT_MAX (8u * 1024u * 1024u)
#define FORK_MMAP_SNAPSHOT_MAX (16u * 1024u * 1024u)

enum process_state {
    PROCESS_FREE = 0,
    PROCESS_RUNNABLE,
    PROCESS_RUNNING,
    PROCESS_BLOCKED,
    PROCESS_STOPPED,
    PROCESS_ZOMBIE,
};

enum process_wait_reason {
    PROCESS_WAIT_NONE = 0,
    PROCESS_WAIT_TTY_READ,
    PROCESS_WAIT_PIPE_READ,
    PROCESS_WAIT_PIPE_WRITE,
    PROCESS_WAIT_WAIT4,
    PROCESS_WAIT_SELECT,
    PROCESS_WAIT_NANOSLEEP,
};

struct process_snapshot {
    bool valid;
    uint8_t* image;
    size_t image_len;
    size_t image_cap;
    uint64_t image_base;
    uint8_t* stack;
    size_t stack_len;
    size_t stack_cap;
    uint64_t stack_base;
    uint8_t* brk;
    size_t brk_len;
    size_t brk_cap;
    uint64_t brk_current;
    uint8_t* mmap;
    size_t mmap_len;
    size_t mmap_cap;
    uint64_t mmap_next;
};

struct process_fd {
    int kind;
    uint32_t flags;
    uint64_t offset;
    int pipe_id;
    struct initramfs_entry entry;
    char path[128];
};

struct process_wait_state {
    enum process_wait_reason reason;
    int nfds;
    int fd;
    int aux0;
    int aux1;
    int aux2;
    uint64_t ptr0;
    uint64_t ptr1;
    uint64_t ptr2;
    uint64_t deadline_ns;
    bool has_timeout;
    uint8_t readfds[PROCESS_SELECT_FDSET_BYTES];
    uint8_t writefds[PROCESS_SELECT_FDSET_BYTES];
    uint8_t exceptfds[PROCESS_SELECT_FDSET_BYTES];
};

struct sigaction_data {
    void* handler;
    uint64_t flags;
    void* restorer;
    uint64_t mask;
};

struct process {
    int pid;
    int ppid;
    int pgid;
    int sid;
    enum process_state state;
    int exit_code;
    int exit_status;
    int last_wait_status;
    int stop_signal;
    bool has_wait_event;
    bool is_child;

    struct process_snapshot snap;
    uint64_t image_start;
    uint64_t image_end;
    struct process_fd fds[PROCESS_MAX_FDS];
    char cwd[128];
    uint64_t brk_current;
    uint64_t mmap_next;
    uint32_t umask;

    struct sigaction_data sig_actions[MAX_SIGNALS];
    uint64_t sig_mask;
    int pending_signals[MAX_PENDING_SIGNALS];
    int pending_count;

    struct syscall_frame saved_frame;
    uint64_t saved_iret[5];
    bool has_saved_context;
    bool resumed_from_block;

    uint64_t fs_base;
    uint64_t tid_address;
    struct process_wait_state wait;
};

void process_init(void);
struct process* process_current(void);
struct process* process_find(int pid);
struct process* process_at(int index);
struct process* process_alloc(void);
void process_free(struct process* proc);

int process_alloc_snapshot(struct process* proc);
void process_free_snapshot(struct process* proc);

int process_send_signal(int pid, int sig);
void process_queue_signal(struct process* proc, int sig);
bool process_has_pending_signal(struct process* proc);
int process_take_pending_signal(struct process* proc);
void process_set_current(struct process* proc);
int process_next_pid(void);
