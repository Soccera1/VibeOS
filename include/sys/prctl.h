#ifndef _SYS_PRCTL_H
#define _SYS_PRCTL_H

#define PR_SET_NAME 15
int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);

#endif
