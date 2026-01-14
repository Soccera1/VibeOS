#ifndef _LIBC_H
#define _LIBC_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <stdio.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <poll.h>
#include <sys/time.h>
#include <glob.h>
#include <sys/resource.h>
#include <setjmp.h>
#include <dirent.h>

extern int errno;
extern int h_errno;
extern char **environ;
const char* hstrerror(int err);

int write(int fd, const void* buf, size_t count);
int read(int fd, void* buf, size_t count);
void exit(int status);
void _exit(int status);
int exec(const char* filename);
int execve(const char* pathname, char* const argv[], char* const envp[]);
int execv(const char* path, char* const argv[]);
int execvp(const char* file, char* const argv[]);
long sysconf(int name);
int ls();

int open(const char* pathname, int flags, ...);
int close(int fd);
int fcntl(int fd, int cmd, ...);
int ioctl(int fd, unsigned long request, ...);
int lseek(int fd, int offset, int whence);
struct stat;
int stat(const char* pathname, struct stat* statbuf);
int lstat(const char* pathname, struct stat* statbuf);
int fstat(int fd, struct stat* statbuf);
int mknod(const char* pathname, mode_t mode, dev_t dev);

pid_t getpid(void);
pid_t getppid(void);
int getrlimit(int resource, struct rlimit* rlp);
int setrlimit(int resource, const struct rlimit* rlp);
int isatty(int fd);
char* ttyname(int fd);
int access(const char* pathname, int mode);
int rename(const char* oldpath, const char* newpath);
int unlink(const char* pathname);
int rmdir(const char* pathname);
int mkdir(const char* pathname, mode_t mode);
int chown(const char* pathname, uid_t owner, gid_t group);
int chmod(const char* pathname, mode_t mode);
mode_t umask(mode_t mask);
int lchown(const char* pathname, uid_t owner, gid_t group);
int symlink(const char *target, const char *linkpath);
int link(const char *oldpath, const char *newpath);

void* brk(void* addr);
void* sbrk(intptr_t increment);
void* malloc(size_t size);
void* realloc(void* ptr, size_t size);
void* calloc(size_t nmemb, size_t size);
void free(void* ptr);
char* getenv(const char* name);
int putenv(char* string);
int setenv(const char* name, const char* value, int overwrite);
int unsetenv(const char* name);
int clearenv(void);
void qsort(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *));
void *bsearch(const void *key, const void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *));
long strtol(const char *nptr, char **endptr, int base);
unsigned long strtoul(const char *nptr, char **endptr, int base);
long long strtoll(const char *nptr, char **endptr, int base);
unsigned long long strtoull(const char *nptr, char **endptr, int base);
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

struct tms;
clock_t times(struct tms* buf);
pid_t fork(void);
pid_t vfork(void);
pid_t setsid(void);
pid_t waitpid(pid_t pid, int* wstatus, int options);
int chdir(const char* path);
int fchdir(int fd);
int chroot(const char* path);
int pipe(int pipefd[2]);
int mkstemp(char* template);
int dup(int oldfd);
int dup2(int oldfd, int newfd);
char* getcwd(char* buf, size_t size);
ssize_t readlink(const char* path, char* buf, size_t bufsiz);
char* realpath(const char* path, char* resolved_path);
int ttyname_r(int fd, char* buf, uint32_t buflen);
void srand(unsigned int seed);
int rand(void);
void* mmap(void* addr, uint32_t length, int prot, int flags, int fd, int32_t offset);
int munmap(void* addr, uint32_t length);
int socket(int domain, int type, int protocol);
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int listen(int sockfd, int backlog);
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
int fileno(void* stream);
char* strndup(const char* s, uint32_t n);
int initgroups(const char *user, gid_t group);
void endgrent(void);
struct passwd;
struct passwd* getpwnam(const char* name);
struct passwd* getpwuid(uid_t uid);
struct group;
struct group* getgrnam(const char* name);
struct group* getgrgid(gid_t gid);
struct timespec;
int nanosleep(const struct timespec *req, struct timespec *rem);
struct termios;
int tcgetattr(int fd, struct termios *termios_p);
int tcsetattr(int fd, int optional_actions, const struct termios *termios_p);
int tcflush(int fd, int queue_selector);
struct pollfd;
int poll(struct pollfd* fds, nfds_t nfds, int timeout);
struct sigaction;
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
int sigfillset(sigset_t *set);
int sigemptyset(sigset_t *set);
int sigaddset(sigset_t *set, int signum);
int sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
int sigsuspend(const sigset_t *mask);
void (*signal(int signum, void (*handler)(int)))(int);
int raise(int sig);
char* strsignal(int sig);
int gettimeofday(struct timeval* tv, struct timezone* tz);
int settimeofday(const struct timeval* tv, const struct timezone* tz);
int utimes(const char* filename, const struct timeval times[2]);
int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
void __assert_fail(const char *assertion, const char *file, unsigned int line, const char *function);
struct utsname;
int uname(struct utsname *buf);
struct hostent;
struct hostent* gethostbyname(const char* name);
struct servent;
struct servent* getservbyname(const char* name, const char* proto);
struct addrinfo;
int getaddrinfo(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** res);
void freeaddrinfo(struct addrinfo* res);
int getnameinfo(const struct sockaddr* sa, socklen_t salen, char* host, socklen_t hostlen, char* serv, socklen_t servlen, int flags);
struct in_addr;
int inet_aton(const char* cp, struct in_addr* inp);
char* inet_ntoa(struct in_addr in);
int fnmatch(const char *pattern, const char *string, int flags);

// String utils
int strcmp(const char* s1, const char* s2);
int strncmp(const char* s1, const char* s2, size_t n);
int strcasecmp(const char* s1, const char* s2);
int strncasecmp(const char* s1, const char* s2, size_t n);
size_t strspn(const char* s, const char* accept);
size_t strcspn(const char* s, const char* reject);
char* strchrnul(const char* s, int c);
size_t strlen(const char* s);
char* strcpy(char* dest, const char* src);
char* stpcpy(char* dest, const char* src);
char* strncpy(char* dest, const char* src, size_t n);
char* stpncpy(char* dest, const char* src, size_t n);
void* memset(void* s, int c, size_t n);
void* memcpy(void* dest, const void* src, size_t n);
void* mempcpy(void* dest, const void* src, size_t n);
void* memmove(void* dest, const void* src, size_t n);
char* strchr(const char* s, int c);
char* strrchr(const char* s, int c);
char* strpbrk(const char* s, const char* accept);
char* strtok_r(char* str, const char* delim, char** saveptr);
char* strstr(const char* haystack, const char* needle);

int putchar(int c);
int puts(const char* s);
int fputc(int c, void* stream);
int putc_unlocked(int c, void* stream);
int fputs(const char* s, void* stream);
char* fgets(char* s, int size, void* stream);
void* fopen(const char* pathname, const char* mode);
void* fdopen(int fd, const char* mode);
void clearerr(void* stream);
ssize_t getline(char** lineptr, size_t* n, void* stream);
int fgetc(void* stream);
int fputc(int c, void* stream);
int getc_unlocked(void* stream);
int fileno(void* stream);
int fclose(void* stream);
int fflush(void* stream);
int ferror(void* stream);
size_t fread(void* ptr, size_t size, size_t nmemb, void* stream);
size_t fwrite(const void* ptr, size_t size, size_t nmemb, void* stream);
int fseeko(void* stream, off_t offset, int whence);
void* freopen(const char* pathname, const char* mode, void* stream);
struct tm;
struct tm* localtime(const time_t* timep);
struct tm* localtime_r(const time_t* timep, struct tm* result);
time_t mktime(struct tm* tm);
size_t strftime(char* s, size_t max, const char* format, const struct tm* tm);
int snprintf(char* str, size_t size, const char* format, ...);
int vsnprintf(char* str, size_t size, const char* format, va_list ap);
int vasprintf(char** strp, const char* fmt, va_list ap);
int sscanf(const char* str, const char* format, ...);
int printf(const char* format, ...);
int vprintf(const char* format, va_list ap);
int fprintf(FILE* stream, const char* format, ...);
int dprintf(int fd, const char* format, ...);
int atoi(const char* nptr);

#endif
