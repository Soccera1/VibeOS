#include "libc.h"
#include <vibeos/syscall.h>
#include <stdio.h>
#include <sys/utsname.h>
#include <time.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <sys/times.h>
#include <pwd.h>

int errno = 0;
int h_errno = 0;
char **environ = NULL;

void *stdin = (void*)0;
void *stdout = (void*)1;
void *stderr = (void*)2;

int *__errno_location(void) {
    return &errno;
}

int mallopt(int param, int value) {
    (void)param; (void)value;
    return 1;
}

unsigned int gnu_dev_major(unsigned long long int dev) {
    return (unsigned int)(dev >> 8);
}

unsigned int gnu_dev_minor(unsigned long long int dev) {
    return (unsigned int)(dev & 0xff);
}

int _setjmp(void *env) {
    (void)env;
    return 0;
}

unsigned long long __isoc23_strtoull(const char *nptr, char **endptr, int base) {
    return strtoull(nptr, endptr, base);
}

long long __isoc23_strtoll(const char *nptr, char **endptr, int base) {
    return strtoll(nptr, endptr, base);
}

unsigned long __isoc23_strtoul(const char *nptr, char **endptr, int base) {
    return strtoul(nptr, endptr, base);
}

long __isoc23_strtol(const char *nptr, char **endptr, int base) {
    return strtol(nptr, endptr, base);
}

int __isoc23_sscanf(const char *str, const char *format, ...) {
    (void)str; (void)format;
    return 0;
}

int putchar_unlocked(int c) {
    return putchar(c);
}

int fputs_unlocked(const char *s, void *stream) {
    return fputs(s, stream);
}

int ferror_unlocked(void *stream) {
    return ferror(stream);
}

int fileno_unlocked(void *stream) {
    return fileno(stream);
}

int __printf_chk(int flag, const char *format, ...) {
    (void)flag; (void)format;
    return 0;
}

int __vfprintf_chk(void *fp, int flag, const char *format, va_list ap) {
    (void)fp; (void)flag; (void)format; (void)ap;
    return 0;
}

int __fprintf_chk(void *fp, int flag, const char *format, ...) {
    (void)fp; (void)flag; (void)format;
    return 0;
}

int __vsnprintf_chk(char *s, size_t maxlen, int flag, size_t slen, const char *format, va_list ap) {
    (void)s; (void)maxlen; (void)flag; (void)slen; (void)format; (void)ap;
    return 0;
}

int __vasprintf_chk(char **ptr, int flag, const char *format, va_list ap) {
    (void)ptr; (void)flag; (void)format; (void)ap;
    return 0;
}

int __sprintf_chk(char *s, int flag, size_t slen, const char *format, ...) {
    (void)s; (void)flag; (void)slen; (void)format;
    return 0;
}

int __vprintf_chk(int flag, const char *format, va_list ap) {
    (void)flag; (void)format; (void)ap;
    return 0;
}

int __dprintf_chk(int fd, int flag, const char *format, ...) {
    (void)fd; (void)flag; (void)format;
    return 0;
}

int __longjmp_chk(void *env, int val) {
    (void)env; (void)val;
    return 0;
}

int optind = 1;
char *optarg = NULL;
int opterr = 1;
int optopt = '?';

static int syscall(int num, int a1, int a2, int a3) {
    int res;
    asm volatile("int $0x80" : "=a"(res) : "a"(num), "b"(a1), "c"(a2), "d"(a3));
    return res;
}

int write(int fd, const void* buf, size_t count) {
    return syscall(SYS_WRITE, fd, (int)buf, count);
}

int read(int fd, void* buf, size_t count) {
    return syscall(SYS_READ, fd, (int)buf, count);
}

void exit(int status) {
    syscall(SYS_EXIT, status, 0, 0);
    while(1);
}

void _exit(int status) {
    exit(status);
}

int exec(const char* filename) {
    return syscall(SYS_EXEC, (int)filename, 0, 0);
}

int execve(const char* pathname, char* const argv[], char* const envp[]) {
    (void)argv; (void)envp;
    return exec(pathname);
}

int execv(const char* path, char* const argv[]) {
    (void)argv;
    return exec(path);
}

int execvp(const char* file, char* const argv[]) {
    (void)argv;
    return exec(file);
}

long sysconf(int name) {
    (void)name;
    return 100;
}

int ls() {
    return syscall(SYS_LS, 0, 0, 0);
}

int open(const char* pathname, int flags, ...) {
    return syscall(SYS_OPEN, (int)pathname, flags, 0);
}

int close(int fd) {
    return syscall(SYS_CLOSE, fd, 0, 0);
}

int fcntl(int fd, int cmd, ...) {
    (void)fd; (void)cmd;
    return 0;
}

int ioctl(int fd, unsigned long request, ...) {
    (void)fd; (void)request;
    return 0;
}

int lseek(int fd, int offset, int whence) {
    return syscall(SYS_LSEEK, fd, offset, whence);
}

int stat(const char* pathname, struct stat* statbuf) {
    return syscall(SYS_STAT, (int)pathname, (int)statbuf, 0);
}

int lstat(const char* pathname, struct stat* statbuf) {
    return stat(pathname, statbuf);
}

int fstat(int fd, struct stat* statbuf) {
    (void)fd; (void)statbuf;
    return -1;
}

int mknod(const char* pathname, mode_t mode, dev_t dev) {
    (void)pathname; (void)mode; (void)dev;
    return -1;
}

pid_t getpid(void) {
    return 1;
}

pid_t getppid(void) {
    return 1;
}

int getrlimit(int resource, struct rlimit* rlp) {
    (void)resource;
    if (rlp) {
        rlp->rlim_cur = RLIM_INFINITY;
        rlp->rlim_max = RLIM_INFINITY;
    }
    return 0;
}

int setrlimit(int resource, const struct rlimit* rlp) {
    (void)resource; (void)rlp;
    return 0;
}

int isatty(int fd) {
    if (fd >= 0 && fd <= 2) return 1;
    return 0;
}

char* ttyname(int fd) {
    (void)fd;
    return "/dev/tty";
}

int access(const char* pathname, int mode) {
    (void)pathname; (void)mode;
    return 0;
}

int rename(const char* oldpath, const char* newpath) {
    (void)oldpath; (void)newpath;
    return -1;
}

int unlink(const char* pathname) {
    (void)pathname;
    return -1;
}

int rmdir(const char* pathname) {
    (void)pathname;
    return -1;
}

int mkdir(const char* pathname, mode_t mode) {
    (void)pathname; (void)mode;
    return -1;
}

int chown(const char* pathname, uid_t owner, gid_t group) {
    (void)pathname; (void)owner; (void)group;
    return 0;
}

int lchown(const char* pathname, uid_t owner, gid_t group) {
    return chown(pathname, owner, group);
}

int chmod(const char* pathname, mode_t mode) {
    (void)pathname; (void)mode;
    return 0;
}

mode_t umask(mode_t mask) {
    (void)mask;
    return 0;
}

int symlink(const char *target, const char *linkpath) {
    (void)target; (void)linkpath;
    return -1;
}

int link(const char *oldpath, const char *newpath) {
    (void)oldpath; (void)newpath;
    return -1;
}

void* brk(void* addr) {
    return (void*)syscall(SYS_BRK, (int)addr, 0, 0);
}

static void* current_break = NULL;

void* sbrk(intptr_t increment) {
    if (current_break == NULL) {
        current_break = brk(0);
    }
    void* old_break = current_break;
    if (increment != 0) {
        current_break = brk((void*)((uint32_t)current_break + increment));
    }
    return old_break;
}

void* malloc(size_t size) {
    return sbrk(size);
}

void* realloc(void* ptr, size_t size) {
    if (!ptr) return malloc(size);
    void* new_ptr = malloc(size);
    if (new_ptr) memcpy(new_ptr, ptr, size);
    return new_ptr;
}

void* calloc(size_t nmemb, size_t size) {
    void* ptr = malloc(nmemb * size);
    if (ptr) memset(ptr, 0, nmemb * size);
    return ptr;
}

void free(void* ptr) {
    (void)ptr;
}

char* getenv(const char* name) {
    (void)name;
    return NULL;
}

int putenv(char* string) { (void)string; return 0; }
int setenv(const char* name, const char* value, int overwrite) { (void)name; (void)value; (void)overwrite; return 0; }
int unsetenv(const char* name) { (void)name; return 0; }
int clearenv(void) { return 0; }

void qsort(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *)) {
    (void)base; (void)nmemb; (void)size; (void)compar;
}

long strtol(const char *nptr, char **endptr, int base) {
    (void)nptr; (void)endptr; (void)base;
    return 0;
}

unsigned long strtoul(const char *nptr, char **endptr, int base) {
    (void)nptr; (void)endptr; (void)base;
    return 0;
}

long long strtoll(const char *nptr, char **endptr, int base) {
    (void)nptr; (void)endptr; (void)base;
    return 0;
}

unsigned long long strtoull(const char *nptr, char **endptr, int base) {
    (void)nptr; (void)endptr; (void)base;
    return 0;
}

unsigned int sleep(unsigned int seconds) {
    for (volatile uint32_t i = 0; i < seconds * 10000000; i++);
    return 0;
}

unsigned int alarm(unsigned int seconds) {
    (void)seconds;
    return 0;
}

int getgroups(int size, gid_t list[]) {
    (void)size; (void)list;
    return 0;
}

uid_t getuid(void) { return 0; }
uid_t geteuid(void) { return 0; }
gid_t getgid(void) { return 0; }
gid_t getegid(void) { return 0; }
int setuid(uid_t uid) { (void)uid; return 0; }
int setgid(gid_t gid) { (void)gid; return 0; }
int seteuid(uid_t euid) { (void)euid; return 0; }
int setegid(gid_t egid) { (void)egid; return 0; }

clock_t times(struct tms* buf) {
    (void)buf;
    return 0;
}

pid_t fork(void) { return -1; }

pid_t vfork(void) {
    return -1; // Not supported
}

pid_t setsid(void) {
    return 1;
}

pid_t waitpid(pid_t pid, int* wstatus, int options) {
    (void)pid; (void)wstatus; (void)options;
    return -1;
}

int chdir(const char* path) { (void)path; return 0; }
int fchdir(int fd) { (void)fd; return 0; }
int chroot(const char* path) { (void)path; return 0; }

int pipe(int pipefd[2]) { (void)pipefd; return -1; }

int mkstemp(char* template) {
    (void)template;
    return -1;
}

int dup(int oldfd) {
    (void)oldfd;
    return -1;
}

int dup2(int oldfd, int newfd) {
    (void)oldfd; (void)newfd;
    return -1;
}

char* getcwd(char* buf, size_t size) {
    if (buf && size > 1) {
        strcpy(buf, "/");
        return buf;
    }
    return NULL;
}

ssize_t readlink(const char* path, char* buf, size_t bufsiz) {
    (void)path; (void)buf; (void)bufsiz;
    return -1;
}

static inline char* strdup_internal(const char* s) {
    size_t len = strlen(s);
    char* d = malloc(len + 1);
    if (d) strcpy(d, s);
    return d;
}

char* realpath(const char* path, char* resolved_path) {
    if (resolved_path) {
        strcpy(resolved_path, path);
        return resolved_path;
    }
    return strdup_internal(path);
}

int ttyname_r(int fd, char* buf, uint32_t buflen) {
    (void)fd; (void)buf; (void)buflen;
    return -1;
}

void srand(unsigned int seed) { (void)seed; }
int rand(void) { return 0; }

void* mmap(void* addr, uint32_t length, int prot, int flags, int fd, int32_t offset) {
    (void)addr; (void)length; (void)prot; (void)flags; (void)fd; (void)offset;
    return MAP_FAILED;
}

int munmap(void* addr, uint32_t length) {
    (void)addr; (void)length;
    return 0;
}

int socket(int domain, int type, int protocol) {
    (void)domain; (void)type; (void)protocol;
    return -1;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    (void)sockfd; (void)addr; (void)addrlen;
    return -1;
}

int listen(int sockfd, int backlog) {
    (void)sockfd; (void)backlog;
    return -1;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
    (void)sockfd; (void)buf; (void)len; (void)flags; (void)dest_addr; (void)addrlen;
    return -1;
}

int fileno(void* stream) {
    return (int)stream;
}

char* strndup(const char* s, uint32_t n) {
    size_t len = strlen(s);
    if (len > n) len = n;
    char* d = malloc(len + 1);
    if (d) {
        memcpy(d, s, len);
        d[len] = '\0';
    }
    return d;
}

int initgroups(const char *user, gid_t group) {
    (void)user; (void)group;
    return 0;
}

void endgrent(void) {}

int nanosleep(const struct timespec *req, struct timespec *rem) {
    (void)req; (void)rem;
    return 0;
}

int tcgetattr(int fd, struct termios *termios_p) {
    (void)fd; (void)termios_p;
    return 0;
}

int tcsetattr(int fd, int optional_actions, const struct termios *termios_p) {
    (void)fd; (void)optional_actions; (void)termios_p;
    return 0;
}

int tcflush(int fd, int queue_selector) {
    (void)fd; (void)queue_selector;
    return 0;
}

int poll(struct pollfd* fds, nfds_t nfds, int timeout) {
    (void)fds; (void)nfds; (void)timeout;
    return 1;
}

int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
    (void)signum; (void)act; (void)oldact;
    return 0;
}

int sigfillset(sigset_t *set) {
    if (set) *set = 0xFFFFFFFF;
    return 0;
}

int sigemptyset(sigset_t *set) {
    if (set) *set = 0;
    return 0;
}

int sigaddset(sigset_t *set, int signum) {
    if (set) *set |= (1 << (signum - 1));
    return 0;
}

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
    (void)how; (void)set; (void)oldset;
    return 0;
}

int sigsuspend(const sigset_t *mask) {
    (void)mask;
    return 0;
}

void (*signal(int signum, void (*handler)(int)))(int) {
    (void)signum; (void)handler;
    return SIG_DFL;
}

int raise(int sig) {
    (void)sig;
    return 0;
}

char* strsignal(int sig) {
    (void)sig;
    return "Unknown signal";
}

int gettimeofday(struct timeval* tv, struct timezone* tz) {
    (void)tv; (void)tz;
    return -1;
}

int settimeofday(const struct timeval* tv, const struct timezone* tz) {
    (void)tv; (void)tz;
    return -1;
}

int utimes(const char* filename, const struct timeval times[2]) {
    (void)filename; (void)times;
    return 0;
}

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    (void)sockfd; (void)addr; (void)addrlen;
    return -1;
}

int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    (void)sockfd; (void)addr; (void)addrlen;
    return -1;
}

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
    (void)sockfd; (void)level; (void)optname; (void)optval; (void)optlen;
    return 0;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    (void)sockfd; (void)addr; (void)addrlen;
    return -1;
}

int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
    (void)option; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return 0;
}

void __assert_fail(const char *assertion, const char *file, unsigned int line, const char *function) {
    (void)assertion; (void)file; (void)line; (void)function;
    exit(1);
}

int uname(struct utsname *buf) {
    if (!buf) return -1;
    strcpy(buf->sysname, "VibeOS");
    strcpy(buf->release, "0.7.0");
    strcpy(buf->machine, "i386");
    return 0;
}

const char* hstrerror(int err) {
    (void)err;
    return "Unknown resolver error";
}

struct hostent* gethostbyname(const char* name) {
    (void)name;
    return NULL;
}

struct servent* getservbyname(const char* name, const char* proto) {
    (void)name; (void)proto;
    return NULL;
}

int getaddrinfo(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** res) {
    (void)node; (void)service; (void)hints; (void)res;
    return -1;
}

void freeaddrinfo(struct addrinfo* res) {
    (void)res;
}

int getnameinfo(const struct sockaddr* sa, socklen_t salen, char* host, socklen_t hostlen, char* serv, socklen_t servlen, int flags) {
    (void)sa; (void)salen; (void)host; (void)hostlen; (void)serv; (void)servlen; (void)flags;
    return -1;
}

int inet_aton(const char* cp, struct in_addr* inp) {
    (void)cp; (void)inp;
    return 0;
}

char* inet_ntoa(struct in_addr in) {
    (void)in;
    return "0.0.0.0";
}

int fnmatch(const char *pattern, const char *string, int flags) {
    (void)pattern; (void)string; (void)flags;
    return -1;
}

DIR *opendir(const char *name) {
    (void)name;
    return NULL;
}

struct dirent *readdir(DIR *dirp) {
    (void)dirp;
    return NULL;
}

int closedir(DIR *dirp) {
    (void)dirp;
    return -1;
}

int setjmp(jmp_buf env) {
    (void)env;
    return 0;
}

void longjmp(jmp_buf env, int val) {
    (void)env; (void)val;
    exit(1);
}

int glob(const char *pattern, int flags, int (*errfunc)(const char *epath, int eerrno), glob_t *pglob) {
    (void)pattern; (void)flags; (void)errfunc; (void)pglob;
    return -1;
}

void globfree(glob_t *pglob) {
    (void)pglob;
}

int getopt(int argc, char * const argv[], const char *optstring) {
    (void)argc; (void)argv; (void)optstring;
    return -1;
}

struct passwd* getpwnam(const char* name) { (void)name; return NULL; }
struct passwd* getpwuid(uid_t uid) { (void)uid; return NULL; }
struct group* getgrnam(const char* name) { (void)name; return NULL; }
struct group* getgrgid(gid_t gid) { (void)gid; return NULL; }

// String utils
int strcmp(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++; s2++;
    }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}

int strncmp(const char* s1, const char* s2, size_t n) {
    if (n == 0) return 0;
    while (n-- > 0 && *s1 && (*s1 == *s2)) {
        if (n == 0) break;
        s1++; s2++;
    }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}

static inline int tolower_internal(int c) {
    return (c >= 'A' && c <= 'Z') ? (c - 'A' + 'a') : c;
}

int strcasecmp(const char* s1, const char* s2) {
    while (*s1 && (tolower_internal(*s1) == tolower_internal(*s2))) {
        s1++; s2++;
    }
    return tolower_internal(*(unsigned char*)s1) - tolower_internal(*(unsigned char*)s2);
}

int strncasecmp(const char* s1, const char* s2, size_t n) {
    if (n == 0) return 0;
    while (n-- > 0 && *s1 && (tolower_internal(*s1) == tolower_internal(*s2))) {
        if (n == 0) break;
        s1++; s2++;
    }
    return tolower_internal(*(unsigned char*)s1) - tolower_internal(*(unsigned char*)s2);
}

size_t strspn(const char* s, const char* accept) {
    size_t count = 0;
    while (*s && strchr(accept, *s++)) count++;
    return count;
}

size_t strcspn(const char* s, const char* reject) {
    size_t count = 0;
    while (*s && !strchr(reject, *s++)) count++;
    return count;
}

char* strchrnul(const char* s, int c) {
    while (*s && *s != (char)c) s++;
    return (char*)s;
}

size_t strlen(const char* s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

char* strcpy(char* dest, const char* src) {
    char* d = dest;
    while ((*d++ = *src++));
    return dest;
}

char* stpcpy(char* dest, const char* src) {
    while ((*dest = *src)) {
        dest++; src++;
    }
    return dest;
}

char* strncpy(char* dest, const char* src, size_t n) {
    char* d = dest;
    while (n > 0 && (*d++ = *src++)) n--;
    while (n > 0) { *d++ = '\0'; n--; } 
    return dest;
}

char* stpncpy(char* dest, const char* src, size_t n) {
    while (n > 0 && (*dest = *src)) {
        dest++; src++; n--;
    }
    while (n > 0) {
        *dest++ = '\0'; n--;
    }
    return dest;
}

void* memset(void* s, int c, size_t n) {
    unsigned char* p = s;
    while (n--) *p++ = (unsigned char)c;
    return s;
}

void* memcpy(void* dest, const void* src, size_t n) {
    unsigned char* d = dest;
    const unsigned char* s = src;
    while (n--) *d++ = *s++;
    return dest;
}

void* mempcpy(void* dest, const void* src, size_t n) {
    return (char*)memcpy(dest, src, n) + n;
}

void* memmove(void* dest, const void* src, size_t n) {
    unsigned char* d = dest;
    const unsigned char* s = src;
    if (d < s) {
        while (n--) *d++ = *s++;
    } else if (d > s) {
        d += n;
        s += n;
        while (n--) *--d = *--s;
    }
    return dest;
}

char* strchr(const char* s, int c) {
    while (*s != (char)c) {
        if (!*s++) return NULL;
    }
    return (char*)s;
}

char* strrchr(const char* s, int c) {
    char* last = NULL;
    do {
        if (*s == (char)c) last = (char*)s;
    } while (*s++);
    return last;
}

char* strpbrk(const char* s, const char* accept) {
    while (*s) {
        if (strchr(accept, *s)) return (char*)s;
        s++;
    }
    return NULL;
}

char* strtok_r(char* str, const char* delim, char** saveptr) {
    (void)str; (void)delim; (void)saveptr;
    return NULL;
}

char* strstr(const char* haystack, const char* needle) {
    if (!*needle) return (char*)haystack;
    for (; *haystack; haystack++) {
        if (*haystack == *needle) {
            const char *h = haystack, *n = needle;
            while (*h && *n && *h == *n) { h++; n++; }
            if (!*n) return (char*)haystack;
        }
    }
    return NULL;
}

int putchar(int c) {
    char b = (char)c;
    write(1, &b, 1);
    return c;
}

int puts(const char* s) {
    write(1, s, strlen(s));
    write(1, "\n", 1);
    return 0;
}

int fputs(const char* s, void* stream) {
    return write((int)stream, s, strlen(s));
}

char* fgets(char* s, int size, void* stream) {
    int i = 0;
    while (i < size - 1) {
        int c = fgetc(stream);
        if (c == -1) {
            if (i == 0) return NULL;
            break;
        }
        s[i++] = (char)c;
        if (c == '\n') break;
    }
    s[i] = '\0';
    return s;
}

void* fopen(const char* pathname, const char* mode) {
    (void)mode;
    int fd = open(pathname, 0);
    if (fd < 0) return NULL;
    return (void*)fd;
}

void* fdopen(int fd, const char* mode) {
    (void)mode;
    return (void*)fd;
}

void clearerr(void* stream) {
    (void)stream;
}

ssize_t getline(char** lineptr, size_t* n, void* stream) {
    if (!lineptr || !n) return -1;
    if (!*lineptr) {
        *n = 128;
        *lineptr = malloc(*n);
    }
    size_t i = 0;
    while (1) {
        if (i >= *n - 1) {
            *n *= 2;
            *lineptr = realloc(*lineptr, *n);
        }
        int c = fgetc(stream);
        if (c == -1) break;
        (*lineptr)[i++] = (char)c;
        if (c == '\n') break;
    }
    (*lineptr)[i] = '\0';
    return (i == 0) ? -1 : (ssize_t)i;
}

int fgetc(void* stream) {
    char c;
    if (read((int)stream, &c, 1) <= 0) return -1;
    return (unsigned char)c;
}

int fputc(int c, void* stream) {
    char b = (char)c;
    write((int)stream, &b, 1);
    return c;
}

int getc_unlocked(void* stream) { return fgetc(stream); }

int putc_unlocked(int c, void* stream) { return fputc(c, stream); }

int fclose(void* stream) { return close((int)stream); }
int fflush(void* stream) { (void)stream; return 0; }
int ferror(void* stream) { (void)stream; return 0; }

size_t fread(void* ptr, size_t size, size_t nmemb, void* stream) {
    return read((int)stream, ptr, size * nmemb) / size;
}

size_t fwrite(const void* ptr, size_t size, size_t nmemb, void* stream) {
    return write((int)stream, ptr, size * nmemb) / size;
}

int fseeko(void* stream, off_t offset, int whence) {
    return lseek((int)stream, offset, whence);
}

void* freopen(const char* pathname, const char* mode, void* stream) {
    (void)pathname; (void)mode; (void)stream;
    return NULL;
}

int printf(const char* format, ...) { (void)format; return 0; }
int vprintf(const char* format, va_list ap) { (void)format; (void)ap; return 0; }
int fprintf(FILE *stream, const char *format, ...) { (void)stream; (void)format; return 0; }
int dprintf(int fd, const char *format, ...) { (void)fd; (void)format; return 0; }
int sprintf(char *str, const char *format, ...) { (void)str; (void)format; return 0; }
int snprintf(char *str, size_t size, const char *format, ...) { (void)str; (void)size; (void)format; return 0; }
int vsnprintf(char *str, size_t size, const char *format, va_list ap) { (void)str; (void)size; (void)format; (void)ap; return 0; }
int vasprintf(char **strp, const char *fmt, va_list ap) { (void)strp; (void)fmt; (void)ap; return -1; }
int sscanf(const char *str, const char *format, ...) { (void)str; (void)format; return 0; }
int vfprintf(FILE *stream, const char *format, va_list ap) { (void)stream; (void)format; (void)ap; return 0; }

int atoi(const char* nptr) {
    int res = 0;
    while (*nptr >= '0' && *nptr <= '9') {
        res = res * 10 + (*nptr - '0');
        nptr++;
    }
    return res;
}

char* strdup(const char* s) {
    return strdup_internal(s);
}

int memcmp(const void* s1, const void* s2, size_t n) {
    const unsigned char *p1 = s1, *p2 = s2;
    while (n--) {
        if (*p1 != *p2) return *p1 - *p2;
        p1++; p2++;
    }
    return 0;
}

char* strerror(int errnum) {
    (void)errnum;
    return "Unknown error";
}

time_t time(time_t *tloc) {
    if (tloc) *tloc = 0;
    return 0;
}

struct tm* localtime_r(const time_t* timep, struct tm* result) {
    (void)timep;
    if (result) memset(result, 0, sizeof(struct tm));
    return result;
}

struct tm* localtime(const time_t* timep) {
    static struct tm res;
    return localtime_r(timep, &res);
}

time_t mktime(struct tm* tm) {
    (void)tm;
    return 0;
}

size_t strftime(char* s, size_t max, const char* format, const struct tm* tm) {
    (void)s; (void)max; (void)format; (void)tm;
    return 0;
}

void* bsearch(const void* key, const void* base, size_t nmemb, size_t size, int (*compar)(const void*, const void*)) {
    (void)key; (void)base; (void)nmemb; (void)size; (void)compar;
    return NULL;
}
