#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_PROCESSES 256
#define MAX_SIGNALS 64
#define MAX_PENDING_SIGNALS 32

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
    PROCESS_ZOMBIE,
};

struct process_snapshot {
    bool valid;
    uint8_t* image;
    size_t image_len;
    uint64_t image_base;
    uint8_t* stack;
    size_t stack_len;
    uint64_t stack_base;
    uint8_t* brk;
    size_t brk_len;
    uint64_t brk_current;
    uint8_t* mmap;
    size_t mmap_len;
    uint64_t mmap_next;
};

struct process_fd {
    int kind;
    uint32_t flags;
    uint64_t offset;
    int pipe_id;
    char path[128];
};

struct sigaction_data {
    void* handler;
    uint64_t flags;
    uint64_t mask;
};

struct process {
    int pid;
    int ppid;
    enum process_state state;
    int exit_code;
    int exit_status;
    bool is_child;

    struct process_snapshot snap;
    struct process_fd fds[64];
    char cwd[128];

    struct sigaction_data sig_actions[MAX_SIGNALS];
    uint64_t sig_mask;
    int pending_signals[MAX_PENDING_SIGNALS];
    int pending_count;

    struct syscall_frame* saved_frame;
    uint64_t saved_iret[5];

    uint64_t fs_base;
    uint64_t tid_address;
};

void process_init(void);
struct process* process_current(void);
struct process* process_find(int pid);
struct process* process_alloc(void);
void process_free(struct process* proc);

int process_alloc_snapshot(struct process* proc);
void process_free_snapshot(struct process* proc);

int process_send_signal(int pid, int sig);
void process_queue_signal(struct process* proc, int sig);
bool process_has_pending_signal(struct process* proc);
int process_take_pending_signal(struct process* proc);