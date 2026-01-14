#ifndef _SYS_IOCTL_H
#define _SYS_IOCTL_H

int ioctl(int fd, unsigned long request, ...);



struct winsize {

    unsigned short ws_row;

    unsigned short ws_col;

    unsigned short ws_xpixel;

    unsigned short ws_ypixel;

};



#define TIOCGWINSZ 0x5413



#endif
