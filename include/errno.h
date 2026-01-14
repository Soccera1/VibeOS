#ifndef _ERRNO_H
#define _ERRNO_H

extern int errno;

#define ENOENT 2
#define EIO    5
#define EINTR  4
#define EBADF  9
#define ENOMEM 12
#define EACCES 13
#define EFAULT 14
#define EAGAIN 11
#define EBUSY  16
#define EEXIST 17
#define ENOEXEC 8
#define ENAMETOOLONG 36
#define ELOOP 40
#define ENOTDIR 20
#define EISDIR 21
#define EINVAL 22
#define ESPIPE 29
#define EXDEV  18
#define ERANGE 34
#define ENOSYS 38
#define EAFNOSUPPORT 97

#endif
