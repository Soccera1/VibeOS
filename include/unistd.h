#ifndef _UNISTD_H
#define _UNISTD_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <user/libc.h>

int read(int fd, void *buf, size_t count);
int write(int fd, const void *buf, size_t count);
int close(int fd);
int lseek(int fd, int offset, int whence);
int unlink(const char *pathname);
int rmdir(const char *pathname);
int mkdir(const char *pathname, mode_t mode);
int chown(const char *pathname, uid_t owner, gid_t group);
int chmod(const char *pathname, mode_t mode);
int symlink(const char *target, const char *linkpath);
int link(const char *oldpath, const char *newpath);
pid_t getpid(void);
pid_t getppid(void);
extern char *optarg;
extern int optind, opterr, optopt;
int getopt(int argc, char * const argv[], const char *optstring);
int isatty(int fd);
char *ttyname(int fd);
int access(const char *pathname, int mode);
unsigned int sleep(unsigned int seconds);
unsigned int alarm(unsigned int seconds);
int getgroups(int size, gid_t list[]);
uid_t getuid(void);
uid_t geteuid(void);
gid_t getgid(void);
gid_t getegid(void);
int setuid(uid_t uid);
int setgid(gid_t gid);
int seteuid(uid_t euid);
int setegid(gid_t egid);
int execve(const char *pathname, char *const argv[], char *const envp[]);
void _exit(int status);
pid_t fork(void);
pid_t vfork(void);
pid_t setsid(void);
int chdir(const char *path);
int fchdir(int fd);
int chroot(const char *path);
int pipe(int pipefd[2]);
int dup(int oldfd);
int dup2(int oldfd, int newfd);
int execv(const char *path, char *const argv[]);
int execvp(const char *file, char *const argv[]);
int ttyname_r(int fd, char *buf, size_t buflen);
char *getcwd(char *buf, size_t size);
ssize_t readlink(const char *path, char *buf, size_t bufsiz);
long sysconf(int name);

#define _SC_CLK_TCK 2

#define F_OK 0
#define X_OK 1
#define W_OK 2
#define R_OK 4

#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

#endif