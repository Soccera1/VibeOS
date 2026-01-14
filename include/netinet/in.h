#ifndef _NETINET_IN_H
#define _NETINET_IN_H

#include <sys/socket.h>

typedef uint32_t in_addr_t;

struct in_addr {
    in_addr_t s_addr;
};

struct sockaddr_in {
    uint16_t sin_family;
    uint16_t sin_port;
    struct in_addr sin_addr;
    char sin_zero[8];
};

#define INADDR_ANY 0

#endif
