#ifndef _NETDB_H
#define _NETDB_H

#include <sys/socket.h>

extern int h_errno;
const char *hstrerror(int err);

struct hostent {
    char  *h_name;
    char **h_aliases;
    int    h_addrtype;
    int    h_length;
    char **h_addr_list;
};

struct hostent *gethostbyname(const char *name);

struct servent {
    char  *s_name;
    char **s_aliases;
    int    s_port;
    char  *s_proto;
};
struct servent *getservbyname(const char *name, const char *proto);

struct addrinfo {
    int              ai_flags;
    int              ai_family;
    int              ai_socktype;
    int              ai_protocol;
    socklen_t        ai_addrlen;
    struct sockaddr *ai_addr;
    char            *ai_canonname;
    struct addrinfo *ai_next;
};

#define AI_CANONNAME    0x0002
#define AI_NUMERICHOST  0x0004

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
void freeaddrinfo(struct addrinfo *res);

#define NI_NUMERICHOST  1
#define NI_NUMERICSERV  2
#define NI_NAMEREQD     8
#define NI_NUMERICSCOPE 32

int getnameinfo(const struct sockaddr *sa, socklen_t salen, char *host, socklen_t hostlen, char *serv, socklen_t servlen, int flags);

#endif
