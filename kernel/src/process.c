#include "process.h"

#include <string.h>

#include "kmalloc.h"

#define USER_BRK_BASE 0x14000000ull
#define USER_MMAP_BASE 0x18000000ull

static struct process g_processes[MAX_PROCESSES];
static struct process* g_current_process = NULL;
static int g_next_pid = 1;

void process_init(void) {
    memset(g_processes, 0, sizeof(g_processes));
    for (int i = 0; i < MAX_PROCESSES; ++i) {
        g_processes[i].pid = 0;
        g_processes[i].state = PROCESS_FREE;
    }

    g_processes[0].pid = 1;
    g_processes[0].ppid = 0;
    g_processes[0].pgid = 1;
    g_processes[0].sid = 1;
    g_processes[0].state = PROCESS_RUNNING;
    g_processes[0].is_child = false;
    g_processes[0].brk_current = USER_BRK_BASE;
    g_processes[0].mmap_next = USER_MMAP_BASE;
    g_processes[0].umask = 022u;
    strcpy(g_processes[0].cwd, "/");
    for (int i = 0; i < PROCESS_MAX_FDS; ++i) {
        g_processes[0].fds[i].kind = 0;
        g_processes[0].fds[i].pipe_id = -1;
    }

    g_current_process = &g_processes[0];
    g_next_pid = 2;
}

struct process* process_current(void) {
    return g_current_process;
}

struct process* process_find(int pid) {
    if (pid < 1) {
        return NULL;
    }
    for (int i = 0; i < MAX_PROCESSES; ++i) {
        if (g_processes[i].pid == pid && g_processes[i].state != PROCESS_FREE) {
            return &g_processes[i];
        }
    }
    return NULL;
}

struct process* process_alloc(void) {
    for (int i = 0; i < MAX_PROCESSES; ++i) {
        if (g_processes[i].state == PROCESS_FREE) {
            struct process* proc = &g_processes[i];
            memset(proc, 0, sizeof(*proc));
            proc->pid = g_next_pid++;
            proc->state = PROCESS_RUNNABLE;
            proc->is_child = false;
            proc->brk_current = USER_BRK_BASE;
            proc->mmap_next = USER_MMAP_BASE;
            proc->umask = 022u;
            for (int j = 0; j < PROCESS_MAX_FDS; ++j) {
                proc->fds[j].pipe_id = -1;
            }
            return proc;
        }
    }
    return NULL;
}

void process_free(struct process* proc) {
    if (proc == NULL) {
        return;
    }

    process_free_snapshot(proc);

    proc->pid = 0;
    proc->state = PROCESS_FREE;
}

struct process* process_at(int index) {
    if (index < 0 || index >= MAX_PROCESSES) {
        return NULL;
    }
    return &g_processes[index];
}

int process_alloc_snapshot(struct process* proc) {
    if (proc == NULL) {
        return -1;
    }

    process_free_snapshot(proc);
    memset(&proc->snap, 0, sizeof(proc->snap));
    proc->snap.valid = true;
    return 0;
}

void process_free_snapshot(struct process* proc) {
    if (proc == NULL) {
        return;
    }

    if (proc->snap.image != NULL) {
        kfree(proc->snap.image);
        proc->snap.image = NULL;
    }
    proc->snap.image_cap = 0;
    if (proc->snap.stack != NULL) {
        kfree(proc->snap.stack);
        proc->snap.stack = NULL;
    }
    proc->snap.stack_cap = 0;
    if (proc->snap.brk != NULL) {
        kfree(proc->snap.brk);
        proc->snap.brk = NULL;
    }
    proc->snap.brk_cap = 0;
    if (proc->snap.mmap != NULL) {
        kfree(proc->snap.mmap);
        proc->snap.mmap = NULL;
    }
    proc->snap.mmap_cap = 0;

    proc->snap.valid = false;
}

int process_send_signal(int pid, int sig) {
    if (sig < 1 || sig >= MAX_SIGNALS) {
        return -22;
    }

    struct process* target = process_find(pid);
    if (target == NULL) {
        return -3;
    }

    if (sig == 0) {
        return 0;
    }

    if (sig == 9 || sig == 19) {
        if (target->state == PROCESS_ZOMBIE) {
            return 0;
        }
        target->exit_code = (sig == 9) ? 137 : 0;
        target->state = PROCESS_ZOMBIE;
        return 0;
    }

    process_queue_signal(target, sig);
    return 0;
}

void process_queue_signal(struct process* proc, int sig) {
    if (proc == NULL || sig < 1 || sig >= MAX_SIGNALS) {
        return;
    }

    if (proc->pending_count >= MAX_PENDING_SIGNALS) {
        return;
    }

    for (int i = 0; i < proc->pending_count; ++i) {
        if (proc->pending_signals[i] == sig) {
            return;
        }
    }

    proc->pending_signals[proc->pending_count++] = sig;
}

bool process_has_pending_signal(struct process* proc) {
    if (proc == NULL || proc->pending_count == 0) {
        return false;
    }

    for (int i = 0; i < proc->pending_count; ++i) {
        int sig = proc->pending_signals[i];
        if (sig >= 1 && sig < MAX_SIGNALS) {
            struct sigaction_data* sa = &proc->sig_actions[sig];
            if (sa->handler != SIGNAL_HANDLER_IGN) {
                return true;
            }
        }
    }
    return false;
}

int process_take_pending_signal(struct process* proc) {
    if (proc == NULL || proc->pending_count == 0) {
        return 0;
    }

    while (proc->pending_count > 0) {
        int sig = proc->pending_signals[0];
        for (int i = 1; i < proc->pending_count; ++i) {
            proc->pending_signals[i - 1] = proc->pending_signals[i];
        }
        proc->pending_count--;

        if (sig >= 1 && sig < MAX_SIGNALS) {
            struct sigaction_data* sa = &proc->sig_actions[sig];
            if (sa->handler != SIGNAL_HANDLER_IGN) {
                return sig;
            }
        }
    }
    return 0;
}

void process_set_current(struct process* proc) {
    g_current_process = proc;
}

int process_next_pid(void) {
    return g_next_pid;
}
