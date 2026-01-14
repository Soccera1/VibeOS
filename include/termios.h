#ifndef _TERMIOS_H
#define _TERMIOS_H

#include <sys/types.h>

typedef uint32_t speed_t;
typedef uint32_t tcflag_t;
typedef unsigned char cc_t;

struct termios {
    tcflag_t c_iflag;
    tcflag_t c_oflag;
    tcflag_t c_cflag;
    tcflag_t c_lflag;
    cc_t c_line;
    cc_t c_cc[32];
    speed_t c_ispeed;
    speed_t c_ospeed;
};

#define ECHO   0000010
#define ECHOE  0000020
#define ECHOK  0000040
#define ECHONL 0000100
#define ICANON 0000002
#define ISIG   0000001

#define IXON   0002000
#define IXOFF  0010000
#define IXANY  0004000
#define BRKINT 0000002
#define INLCR  0000100
#define ICRNL  0000400
#define IUCLC  0001000
#define IMAXBEL 0020000

#define ONLCR  0000004

#define VMIN   6
#define VTIME  5

#define TCSANOW 0
#define TCIFLUSH 0

#define B0 0
#define B50 1
#define B75 2
#define B110 3
#define B134 4
#define B150 5
#define B200 6
#define B300 7
#define B600 8
#define B1200 9
#define B1800 10
#define B2400 11
#define B4800 12
#define B9600 13
#define B19200 14
#define B38400 15

int tcgetattr(int fd, struct termios *termios_p);
int tcsetattr(int fd, int optional_actions, const struct termios *termios_p);
int tcflush(int fd, int queue_selector);

#endif
