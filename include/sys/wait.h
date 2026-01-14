#ifndef _SYS_WAIT_H
#define _SYS_WAIT_H

#include <sys/types.h>

pid_t waitpid(pid_t pid, int *wstatus, int options);

#define WNOHANG 1

#define WIFEXITED(s)    (((s) & 0x7f) == 0)
#define WEXITSTATUS(s)  (((s) & 0xff00) >> 8)
#define WIFSIGNALED(s)  (((s) & 0x7f) > 0 && ((s) & 0x7f) < 0x7f)
#define WTERMSIG(s)     ((s) & 0x7f)
#define WCOREDUMP(s)    ((s) & 0x80)

#endif
