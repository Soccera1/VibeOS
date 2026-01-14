#ifndef _SYS_RESOURCE_H
#define _SYS_RESOURCE_H

#include <sys/types.h>

typedef uint32_t rlim_t;

struct rlimit {
    rlim_t rlim_cur;
    rlim_t rlim_max;
};

#define RLIM_INFINITY ((rlim_t)-1)

#define RLIMIT_CORE   4
#define RLIMIT_DATA   2
#define RLIMIT_FSIZE  1

int getrlimit(int resource, struct rlimit *rlp);
int setrlimit(int resource, const struct rlimit *rlp);

#endif
