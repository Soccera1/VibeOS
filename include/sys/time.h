#ifndef _SYS_TIME_H
#define _SYS_TIME_H

#include <sys/types.h>

struct timeval {
    long tv_sec;
    long tv_usec;
};

struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};

int settimeofday(const struct timeval *tv, const struct timezone *tz);

int gettimeofday(struct timeval *tv, struct timezone *tz);

int utimes(const char *filename, const struct timeval times[2]);



#endif
