#ifndef _POLL_H
#define _POLL_H

#include <sys/types.h>

typedef uint32_t nfds_t;



struct pollfd {

    int fd;

    short events;

    short revents;

};



#define POLLIN 0x001



int poll(struct pollfd *fds, nfds_t nfds, int timeout);



#endif
