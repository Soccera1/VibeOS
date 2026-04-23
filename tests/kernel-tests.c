#define _GNU_SOURCE

#include <asm/prctl.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <sys/prctl.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <linux/futex.h>

#ifndef F_DUPFD_CLOEXEC
#define F_DUPFD_CLOEXEC 1030
#endif

static const char* k_helper_path = "/usr/libexec/kernel-tests/kernel-test-helper";
static const char* k_helper_link = "/usr/share/kernel-tests/helper-link";
static const char* k_listener_path = "/var/kernel-test.sock";

static const char* g_current_test = NULL;
static int g_failures = 0;
static int g_checks = 0;

static void record_failure(int line, const char* fmt, ...) {
    va_list ap;

    ++g_failures;
    fprintf(stderr, "[FAIL] %s:%d: ", g_current_test != NULL ? g_current_test : "(unknown)", line);

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fputc('\n', stderr);
}

#define REQUIRE(cond, ...)                       \
    do {                                         \
        ++g_checks;                              \
        if (!(cond)) {                           \
            record_failure(__LINE__, __VA_ARGS__); \
            return;                              \
        }                                        \
    } while (0)

static void write_all(int fd, const void* buf, size_t len) {
    const unsigned char* p = (const unsigned char*)buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        p += (size_t)n;
        len -= (size_t)n;
    }
}

static ssize_t read_all_into_buffer(int fd, char* buf, size_t cap) {
    size_t used = 0;
    while (used + 1 < cap) {
        ssize_t n = read(fd, buf + used, cap - used - 1);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            break;
        }
        used += (size_t)n;
    }
    buf[used] = '\0';
    return (ssize_t)used;
}

static void fill_sockaddr(struct sockaddr_un* addr, const char* path, socklen_t* addrlen) {
    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    strncpy(addr->sun_path, path, sizeof(addr->sun_path) - 1);
    *addrlen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + strlen(addr->sun_path) + 1);
}

static void wait_for_exit_code(pid_t pid, int expected) {
    int status = 0;
    pid_t got = -1;
    do {
        got = waitpid(pid, &status, 0);
    } while (got < 0 && errno == EINTR);
    REQUIRE(got == pid, "waitpid(%d) returned %d: %s", (int)pid, (int)got, strerror(errno));
    REQUIRE(WIFEXITED(status), "child %d did not exit normally: status=0x%x", (int)pid, status);
    REQUIRE(WEXITSTATUS(status) == expected, "child %d exit code %d != %d", (int)pid, WEXITSTATUS(status), expected);
}

static pid_t waitpid_retry(pid_t pid, int* status, int options) {
    pid_t got = -1;
    do {
        got = waitpid(pid, status, options);
    } while (got < 0 && errno == EINTR);
    return got;
}

static void test_identity_and_paths(void) {
    struct utsname uts;
    char cwd[256];
    int fd = -1;
    int dirfd = -1;
    int linkfd = -1;
    ssize_t n = 0;
    char linkbuf[256];
    struct stat st;
    struct stat lst;
    struct statx stx;
    DIR* dir = NULL;
    struct dirent* ent = NULL;
    bool found_helper = false;
    bool found_self = false;

    REQUIRE(uname(&uts) == 0, "uname failed: %s", strerror(errno));
    REQUIRE(strcmp(uts.sysname, "VibeOS") == 0, "unexpected sysname: %s", uts.sysname);
    REQUIRE(strcmp(uts.machine, "x86_64") == 0, "unexpected machine: %s", uts.machine);
    REQUIRE(getpid() > 0, "getpid returned %d", (int)getpid());
    REQUIRE(getppid() >= 0, "getppid returned %d", (int)getppid());
    REQUIRE(getuid() == 0 && geteuid() == 0, "uid/euid were not zero");
    REQUIRE(getgid() == 0 && getegid() == 0, "gid/egid were not zero");

    REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL, "getcwd(/) failed: %s", strerror(errno));
    REQUIRE(strcmp(cwd, "/") == 0, "initial cwd was %s", cwd);

    REQUIRE(chdir("/usr") == 0, "chdir(/usr) failed: %s", strerror(errno));
    REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL, "getcwd(/usr) failed: %s", strerror(errno));
    REQUIRE(strcmp(cwd, "/usr") == 0, "cwd after chdir(/usr) was %s", cwd);

    dirfd = open(".", O_RDONLY | O_DIRECTORY);
    REQUIRE(dirfd >= 0, "open(.) failed: %s", strerror(errno));

    fd = openat(dirfd, "bin/kernel-tests", O_RDONLY);
    REQUIRE(fd >= 0, "openat(bin/kernel-tests) failed: %s", strerror(errno));
    close(fd);
    fd = -1;

    REQUIRE(access(k_helper_path, X_OK) == 0, "access(%s) failed: %s", k_helper_path, strerror(errno));

    n = readlink("/proc/self/exe", linkbuf, sizeof(linkbuf) - 1);
    REQUIRE(n >= 0, "readlink(/proc/self/exe) failed: %s", strerror(errno));
    linkbuf[n] = '\0';
    REQUIRE(strcmp(linkbuf, "/bin/busybox") == 0, "unexpected /proc/self/exe target: %s", linkbuf);

    REQUIRE(stat(k_helper_path, &st) == 0, "stat(%s) failed: %s", k_helper_path, strerror(errno));
    REQUIRE(S_ISREG(st.st_mode), "%s was not a regular file", k_helper_path);
    REQUIRE(st.st_size > 0, "%s had zero size", k_helper_path);

    REQUIRE(lstat(k_helper_link, &lst) == 0, "lstat(%s) failed: %s", k_helper_link, strerror(errno));
    REQUIRE(S_ISLNK(lst.st_mode), "%s was not a symlink", k_helper_link);

    memset(linkbuf, 0, sizeof(linkbuf));
    n = readlink(k_helper_link, linkbuf, sizeof(linkbuf) - 1);
    REQUIRE(n >= 0, "readlink(%s) failed: %s", k_helper_link, strerror(errno));
    linkbuf[n] = '\0';
    REQUIRE(strcmp(linkbuf, "../../libexec/kernel-tests/kernel-test-helper") == 0,
            "unexpected helper symlink target: %s", linkbuf);

    memset(&stx, 0, sizeof(stx));
    REQUIRE(syscall(SYS_statx, AT_FDCWD, k_helper_path, 0, STATX_TYPE | STATX_SIZE, &stx) == 0,
            "statx(%s) failed: %s", k_helper_path, strerror(errno));
    REQUIRE((stx.stx_mode & S_IFMT) == S_IFREG, "statx mode 0%o was not regular", stx.stx_mode);
    REQUIRE(stx.stx_size == (uint64_t)st.st_size, "statx size %llu != stat size %lld",
            (unsigned long long)stx.stx_size, (long long)st.st_size);

    dir = opendir("/usr/libexec/kernel-tests");
    REQUIRE(dir != NULL, "opendir(/usr/libexec/kernel-tests) failed: %s", strerror(errno));
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
            continue;
        }
        if (strcmp(ent->d_name, "kernel-test-helper") == 0) {
            found_helper = true;
        }
        if (strcmp(ent->d_name, "kernel-tests") == 0) {
            found_self = true;
        }
    }
    REQUIRE(found_helper, "kernel-test-helper was missing from directory listing");
    REQUIRE(!found_self, "unexpected kernel-tests binary in helper directory");

    REQUIRE(chdir("/") == 0, "chdir(/) failed: %s", strerror(errno));

    if (dir != NULL) {
        closedir(dir);
    }
    if (linkfd >= 0) {
        close(linkfd);
    }
    if (fd >= 0) {
        close(fd);
    }
    if (dirfd >= 0) {
        close(dirfd);
    }
}

static void test_file_io_and_mmap(void) {
    int fd = -1;
    int dirfd = -1;
    int pipefd[2] = { -1, -1 };
    unsigned char elf[8];
    unsigned char via_readv[8];
    struct iovec iov[2];
    off_t end = 0;
    ssize_t n = 0;
    void* map = MAP_FAILED;
    char motd[128];

    fd = open(k_helper_path, O_RDONLY);
    REQUIRE(fd >= 0, "open(%s) failed: %s", k_helper_path, strerror(errno));

    memset(elf, 0, sizeof(elf));
    REQUIRE(pread(fd, elf, sizeof(elf), 0) == (ssize_t)sizeof(elf), "pread helper ELF header failed: %s", strerror(errno));
    REQUIRE(memcmp(elf, "\x7f""ELF", 4) == 0, "helper ELF magic was invalid");

    end = lseek(fd, 0, SEEK_END);
    REQUIRE(end > 0, "lseek(SEEK_END) returned %lld", (long long)end);
    REQUIRE(lseek(fd, 0, SEEK_SET) == 0, "lseek(SEEK_SET) failed: %s", strerror(errno));

    memset(via_readv, 0, sizeof(via_readv));
    iov[0].iov_base = via_readv;
    iov[0].iov_len = 4;
    iov[1].iov_base = via_readv + 4;
    iov[1].iov_len = 4;
    REQUIRE(readv(fd, iov, 2) == 8, "readv(helper) failed: %s", strerror(errno));
    REQUIRE(memcmp(via_readv, elf, sizeof(elf)) == 0, "readv bytes did not match pread bytes");

    REQUIRE(pipe(pipefd) == 0, "pipe for sendfile failed: %s", strerror(errno));
    REQUIRE(lseek(fd, 0, SEEK_SET) == 0, "reset helper offset failed: %s", strerror(errno));
    REQUIRE(sendfile(pipefd[1], fd, NULL, 8) == 8, "sendfile(helper->pipe) failed: %s", strerror(errno));
    memset(via_readv, 0, sizeof(via_readv));
    REQUIRE(read(pipefd[0], via_readv, 8) == 8, "read(sendfile pipe) failed: %s", strerror(errno));
    REQUIRE(memcmp(via_readv, elf, sizeof(elf)) == 0, "sendfile bytes did not match helper ELF header");
    close(pipefd[0]);
    close(pipefd[1]);
    pipefd[0] = -1;
    pipefd[1] = -1;

    map = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    REQUIRE(map != MAP_FAILED, "mmap(helper) failed: %s", strerror(errno));
    REQUIRE(memcmp(map, "\x7f""ELF", 4) == 0, "mapped helper bytes did not start with ELF magic");
    REQUIRE(munmap(map, 4096) == 0, "munmap(helper) failed: %s", strerror(errno));
    map = MAP_FAILED;

    dirfd = open("/usr/libexec/kernel-tests", O_RDONLY | O_DIRECTORY);
    REQUIRE(dirfd >= 0, "open(helper dir) failed: %s", strerror(errno));
    errno = 0;
    n = read(dirfd, motd, sizeof(motd));
    REQUIRE(n == -1 && errno == EISDIR, "reading a directory returned %zd with errno=%d", n, errno);

    close(dirfd);
    dirfd = -1;
    close(fd);
    fd = -1;

    fd = open("/etc/motd", O_RDONLY);
    REQUIRE(fd >= 0, "open(/etc/motd) failed: %s", strerror(errno));
    memset(motd, 0, sizeof(motd));
    REQUIRE(read(fd, motd, sizeof(motd) - 1) > 0, "read(/etc/motd) failed: %s", strerror(errno));
    REQUIRE(strstr(motd, "VibeOS") != NULL, "/etc/motd did not mention VibeOS");

    if (map != MAP_FAILED) {
        munmap(map, 4096);
    }
    if (pipefd[0] >= 0) {
        close(pipefd[0]);
    }
    if (pipefd[1] >= 0) {
        close(pipefd[1]);
    }
    if (dirfd >= 0) {
        close(dirfd);
    }
    if (fd >= 0) {
        close(fd);
    }
}

static void test_pipes_select_and_poll(void) {
    int pipefd[2] = { -1, -1 };
    int dupfd = -1;
    struct iovec wiov[3];
    struct iovec riov[2];
    char left[8];
    char right[8];
    char readbuf[16];
    char one = 0;
    struct pollfd pfd;
    fd_set rfds;
    struct timeval tv;
    int ready = 0;
    ssize_t n = 0;

    REQUIRE(pipe(pipefd) == 0, "pipe failed: %s", strerror(errno));

    wiov[0].iov_base = "hello";
    wiov[0].iov_len = 5;
    wiov[1].iov_base = "-";
    wiov[1].iov_len = 1;
    wiov[2].iov_base = "world";
    wiov[2].iov_len = 5;
    REQUIRE(writev(pipefd[1], wiov, 3) == 11, "writev(pipe) failed: %s", strerror(errno));

    memset(left, 0, sizeof(left));
    memset(right, 0, sizeof(right));
    riov[0].iov_base = left;
    riov[0].iov_len = 6;
    riov[1].iov_base = right;
    riov[1].iov_len = 5;
    REQUIRE(readv(pipefd[0], riov, 2) == 11, "readv(pipe) failed: %s", strerror(errno));
    REQUIRE(strcmp(left, "hello-") == 0, "unexpected left readv payload: %s", left);
    REQUIRE(memcmp(right, "world", 5) == 0, "unexpected right readv payload");

    pfd.fd = pipefd[0];
    pfd.events = POLLIN;
    pfd.revents = 0;
    REQUIRE(poll(&pfd, 1, 0) == 0, "poll(empty read pipe) was unexpectedly ready");

    pfd.fd = pipefd[1];
    pfd.events = POLLOUT;
    pfd.revents = 0;
    REQUIRE(poll(&pfd, 1, 0) == 1, "poll(write pipe) did not report ready");
    REQUIRE((pfd.revents & POLLOUT) != 0, "poll(write pipe) lacked POLLOUT");

    REQUIRE(fcntl(pipefd[0], F_SETFL, O_RDONLY | O_NONBLOCK) == 0, "F_SETFL(O_NONBLOCK) failed: %s", strerror(errno));
    errno = 0;
    n = read(pipefd[0], &one, 1);
    REQUIRE(n == -1 && errno == EAGAIN, "nonblocking pipe read returned %zd with errno=%d", n, errno);
    REQUIRE(fcntl(pipefd[0], F_SETFL, O_RDONLY) == 0, "F_SETFL(blocking) failed: %s", strerror(errno));

    dupfd = dup2(pipefd[1], 31);
    REQUIRE(dupfd == 31, "dup2(pipe write, 31) returned %d", dupfd);
    close(pipefd[1]);
    pipefd[1] = -1;
    REQUIRE(write(dupfd, "Z", 1) == 1, "write(dupfd) failed: %s", strerror(errno));

    FD_ZERO(&rfds);
    FD_SET(pipefd[0], &rfds);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    ready = select(pipefd[0] + 1, &rfds, NULL, NULL, &tv);
    REQUIRE(ready == 1, "select(pipe read) returned %d", ready);
    REQUIRE(FD_ISSET(pipefd[0], &rfds), "select(pipe read) did not set the fd bit");
    REQUIRE(read(pipefd[0], readbuf, 1) == 1, "read after select failed: %s", strerror(errno));
    REQUIRE(readbuf[0] == 'Z', "read after select returned %c", readbuf[0]);

    close(dupfd);
    dupfd = -1;
    close(pipefd[0]);
    pipefd[0] = -1;
}

static void test_socketpair_and_unix_sockets(void) {
    int sv[2] = { -1, -1 };
    int listener = -1;
    int client = -1;
    int accepted = -1;
    struct sockaddr_un addr;
    struct sockaddr_un peer;
    socklen_t addrlen = 0;
    socklen_t peerlen = sizeof(peer);
    char buf[32];
    int pending = 0;
    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair failed: %s", strerror(errno));
    REQUIRE(write(sv[0], "pair", 4) == 4, "socketpair write failed: %s", strerror(errno));
    REQUIRE(ioctl(sv[1], FIONREAD, &pending) == 0, "socketpair FIONREAD failed: %s", strerror(errno));
    REQUIRE(pending == 4, "socketpair FIONREAD reported %d", pending);
    memset(buf, 0, sizeof(buf));
    REQUIRE(read(sv[1], buf, sizeof(buf)) == 4, "socketpair read failed: %s", strerror(errno));
    REQUIRE(strcmp(buf, "pair") == 0, "socketpair payload mismatch: %s", buf);
    REQUIRE(shutdown(sv[0], SHUT_WR) == 0, "socketpair shutdown(SHUT_WR) failed: %s", strerror(errno));
    REQUIRE(read(sv[1], buf, sizeof(buf)) == 0, "socketpair EOF after shutdown was missing");
    close(sv[0]);
    close(sv[1]);
    sv[0] = -1;
    sv[1] = -1;

    listener = socket(AF_UNIX, SOCK_STREAM, 0);
    REQUIRE(listener >= 0, "socket(listener) failed: %s", strerror(errno));
    fill_sockaddr(&addr, k_listener_path, &addrlen);
    REQUIRE(bind(listener, (const struct sockaddr*)&addr, addrlen) == 0, "bind(%s) failed: %s", k_listener_path, strerror(errno));
    REQUIRE(listen(listener, 4) == 0, "listen(%s) failed: %s", k_listener_path, strerror(errno));

    client = socket(AF_UNIX, SOCK_STREAM, 0);
    REQUIRE(client >= 0, "socket(client) failed: %s", strerror(errno));
    REQUIRE(connect(client, (const struct sockaddr*)&addr, addrlen) == 0, "connect(%s) failed: %s", k_listener_path, strerror(errno));

    pending = 0;
    REQUIRE(ioctl(listener, FIONREAD, &pending) == 0, "listener FIONREAD failed: %s", strerror(errno));
    REQUIRE(pending == 1, "listener pending queue depth was %d", pending);

    memset(&peer, 0, sizeof(peer));
    peerlen = sizeof(peer);
    accepted = accept(listener, (struct sockaddr*)&peer, &peerlen);
    REQUIRE(accepted >= 0, "accept failed: %s", strerror(errno));
    REQUIRE(peer.sun_family == AF_UNIX, "accept peer family was %d", peer.sun_family);
    REQUIRE(strlen(peer.sun_path) == 0, "accepted peer path was expected to be empty but was %s", peer.sun_path);

    memset(&peer, 0, sizeof(peer));
    peerlen = sizeof(peer);
    REQUIRE(getsockname(listener, (struct sockaddr*)&peer, &peerlen) == 0, "getsockname(listener) failed: %s", strerror(errno));
    REQUIRE(strcmp(peer.sun_path, k_listener_path) == 0, "listener path mismatch: %s", peer.sun_path);

    memset(&peer, 0, sizeof(peer));
    peerlen = sizeof(peer);
    REQUIRE(getpeername(client, (struct sockaddr*)&peer, &peerlen) == 0, "getpeername(client) failed: %s", strerror(errno));
    REQUIRE(strcmp(peer.sun_path, k_listener_path) == 0, "client peer path mismatch: %s", peer.sun_path);

    REQUIRE(write(client, "unix", 4) == 4, "write(client) failed: %s", strerror(errno));
    memset(buf, 0, sizeof(buf));
    REQUIRE(read(accepted, buf, sizeof(buf)) == 4, "read(accepted) failed: %s", strerror(errno));
    REQUIRE(strcmp(buf, "unix") == 0, "accepted socket payload mismatch: %s", buf);
    REQUIRE(shutdown(client, SHUT_WR) == 0, "shutdown(client, SHUT_WR) failed: %s", strerror(errno));
    REQUIRE(read(accepted, buf, sizeof(buf)) == 0, "accepted socket EOF after shutdown was missing");

    if (accepted >= 0) {
        close(accepted);
    }
    if (client >= 0) {
        close(client);
    }
    if (listener >= 0) {
        close(listener);
    }
}

static void test_process_wait_and_exec(void) {
    int gate[2] = { -1, -1 };
    int out[2] = { -1, -1 };
    int status = 0;
    int cloexec_fd = -1;
    char output[256];
    char fd_text[32];
    pid_t child = -1;
    pid_t got = -1;

    REQUIRE(pipe(gate) == 0, "pipe(gate) failed: %s", strerror(errno));
    child = fork();
    REQUIRE(child >= 0, "fork(wait-nohang child) failed: %s", strerror(errno));
    if (child == 0) {
        char token = 0;
        close(gate[1]);
        if (read(gate[0], &token, 1) != 1) {
            _exit(90);
        }
        _exit(12);
    }

    close(gate[0]);
    gate[0] = -1;
    status = 0;
    got = waitpid_retry(child, &status, WNOHANG);
    REQUIRE(got == 0, "waitpid(WNOHANG) returned %d", (int)got);
    REQUIRE(write(gate[1], "x", 1) == 1, "release write failed: %s", strerror(errno));
    close(gate[1]);
    gate[1] = -1;
    wait_for_exit_code(child, 12);
    child = -1;

    REQUIRE(pipe(out) == 0, "pipe(out) failed: %s", strerror(errno));
    child = fork();
    REQUIRE(child >= 0, "fork(exec child) failed: %s", strerror(errno));
    if (child == 0) {
        char* const argv[] = {
            (char*)k_helper_path,
            (char*)"print-env",
            (char*)"tagged",
            NULL,
        };
        char* const envp[] = {
            (char*)"KERNEL_TEST_ENV=present",
            (char*)"PATH=/usr/bin:/bin",
            NULL,
        };

        close(out[0]);
        if (dup2(out[1], STDOUT_FILENO) < 0) {
            _exit(91);
        }
        close(out[1]);
        execve(k_helper_path, argv, envp);
        _exit(92);
    }

    close(out[1]);
    out[1] = -1;
    memset(output, 0, sizeof(output));
    REQUIRE(read_all_into_buffer(out[0], output, sizeof(output)) >= 0, "read(exec output) failed: %s", strerror(errno));
    close(out[0]);
    out[0] = -1;
    wait_for_exit_code(child, 0);
    child = -1;
    REQUIRE(strstr(output, "argc=3") != NULL, "exec output missing argc: %s", output);
    REQUIRE(strstr(output, "argv1=print-env") != NULL, "exec output missing argv1: %s", output);
    REQUIRE(strstr(output, "argv2=tagged") != NULL, "exec output missing argv2: %s", output);
    REQUIRE(strstr(output, "env=present") != NULL, "exec output missing env: %s", output);

    REQUIRE(pipe(out) == 0, "pipe(cloexec) failed: %s", strerror(errno));
    cloexec_fd = fcntl(out[1], F_DUPFD_CLOEXEC, 20);
    REQUIRE(cloexec_fd >= 20, "F_DUPFD_CLOEXEC returned %d", cloexec_fd);
    snprintf(fd_text, sizeof(fd_text), "%d", cloexec_fd);

    child = fork();
    REQUIRE(child >= 0, "fork(cloexec child) failed: %s", strerror(errno));
    if (child == 0) {
        char* const argv[] = {
            (char*)k_helper_path,
            (char*)"check-fd-closed",
            fd_text,
            NULL,
        };

        close(out[0]);
        close(out[1]);
        execv(k_helper_path, argv);
        _exit(93);
    }

    close(out[0]);
    out[0] = -1;
    close(out[1]);
    out[1] = -1;
    close(cloexec_fd);
    cloexec_fd = -1;
    wait_for_exit_code(child, 0);

    if (gate[0] >= 0) {
        close(gate[0]);
    }
    if (gate[1] >= 0) {
        close(gate[1]);
    }
    if (out[0] >= 0) {
        close(out[0]);
    }
    if (out[1] >= 0) {
        close(out[1]);
    }
    if (cloexec_fd >= 0) {
        close(cloexec_fd);
    }
}

static void test_process_groups_and_signals(void) {
    int gate[2] = { -1, -1 };
    int report[2] = { -1, -1 };
    int status = 0;
    int child_status = 0;
    pid_t child = -1;
    pid_t group_child = -1;
    pid_t session_child = -1;
    pid_t got = -1;

    REQUIRE(pipe(gate) == 0, "pipe(signal gate) failed: %s", strerror(errno));
    child = fork();
    REQUIRE(child >= 0, "fork(signal child) failed: %s", strerror(errno));
    if (child == 0) {
        char token = 0;
        ssize_t n = 0;
        close(gate[1]);
        for (;;) {
            n = read(gate[0], &token, 1);
            if (n >= 0) {
                break;
            }
            if (errno != EINTR) {
                _exit(96);
            }
        }
        _exit(0);
    }

    close(gate[0]);
    gate[0] = -1;
    REQUIRE(kill(child, SIGSTOP) == 0, "kill(SIGSTOP) failed: %s", strerror(errno));
    got = waitpid_retry(child, &status, WUNTRACED);
    REQUIRE(got == child, "waitpid(WUNTRACED) returned %d", (int)got);
    REQUIRE(WIFSTOPPED(status), "child status 0x%x was not stopped", status);
    REQUIRE(WSTOPSIG(status) == SIGSTOP, "stopped child signal %d != SIGSTOP", WSTOPSIG(status));

    REQUIRE(kill(child, SIGCONT) == 0, "kill(SIGCONT) failed: %s", strerror(errno));
    got = waitpid_retry(child, &status, WCONTINUED);
    REQUIRE(got == child, "waitpid(WCONTINUED) returned %d", (int)got);
    REQUIRE(WIFCONTINUED(status), "child status 0x%x was not continued", status);

    REQUIRE(kill(child, SIGTERM) == 0, "kill(SIGTERM) failed: %s", strerror(errno));
    got = waitpid_retry(child, &status, 0);
    REQUIRE(got == child, "waitpid(SIGTERM child) returned %d", (int)got);
    REQUIRE(WIFSIGNALED(status), "SIGTERM child status 0x%x was not signaled", status);
    REQUIRE(WTERMSIG(status) == SIGTERM, "SIGTERM child signal %d != SIGTERM", WTERMSIG(status));
    close(gate[1]);
    gate[1] = -1;

    REQUIRE(pipe(gate) == 0, "pipe(group gate) failed: %s", strerror(errno));
    group_child = fork();
    REQUIRE(group_child >= 0, "fork(group child) failed: %s", strerror(errno));
    if (group_child == 0) {
        char token = 0;
        close(gate[1]);
        (void)read(gate[0], &token, 1);
        _exit(0);
    }

    close(gate[0]);
    gate[0] = -1;
    REQUIRE(setpgid(group_child, group_child) == 0, "setpgid(%d,%d) failed: %s",
            (int)group_child, (int)group_child, strerror(errno));
    REQUIRE(getpgid(group_child) == group_child, "getpgid(%d) returned %d", (int)group_child, (int)getpgid(group_child));
    REQUIRE(kill(-group_child, SIGTERM) == 0, "kill(-%d, SIGTERM) failed: %s", (int)group_child, strerror(errno));
    got = waitpid_retry(group_child, &status, 0);
    REQUIRE(got == group_child, "waitpid(group child) returned %d", (int)got);
    REQUIRE(WIFSIGNALED(status), "group child status 0x%x was not signaled", status);
    REQUIRE(WTERMSIG(status) == SIGTERM, "group child signal %d != SIGTERM", WTERMSIG(status));
    close(gate[1]);
    gate[1] = -1;

    REQUIRE(pipe(report) == 0, "pipe(session report) failed: %s", strerror(errno));
    session_child = fork();
    REQUIRE(session_child >= 0, "fork(session child) failed: %s", strerror(errno));
    if (session_child == 0) {
        pid_t sid = 0;
        pid_t pgrp = 0;

        close(report[0]);
        sid = setsid();
        if (sid < 0) {
            child_status = 94;
        } else {
            pgrp = getpgrp();
            child_status = (sid == getpid() && pgrp == getpid()) ? 0 : 95;
        }
        write_all(report[1], &child_status, sizeof(child_status));
        close(report[1]);
        _exit(child_status);
    }

    close(report[1]);
    report[1] = -1;
    memset(&child_status, 0, sizeof(child_status));
    REQUIRE(read(report[0], &child_status, sizeof(child_status)) == (ssize_t)sizeof(child_status),
            "read(session report) failed: %s", strerror(errno));
    close(report[0]);
    report[0] = -1;
    wait_for_exit_code(session_child, 0);
    REQUIRE(child_status == 0, "session child reported %d", child_status);

    if (gate[0] >= 0) {
        close(gate[0]);
    }
    if (gate[1] >= 0) {
        close(gate[1]);
    }
    if (report[0] >= 0) {
        close(report[0]);
    }
    if (report[1] >= 0) {
        close(report[1]);
    }
}

static void test_memory_and_misc(void) {
    struct timespec ts0;
    struct timespec ts1;
    struct rlimit lim;
    struct rlimit lim2;
    unsigned char rnd[32];
    void* map = MAP_FAILED;
    long brk_now = 0;
    long brk_after = 0;
    long brk_restore = 0;
    uint64_t fs_base = 0;
    uint64_t fs_probe = 0;
    size_t i = 0;
    bool all_zero = true;

    REQUIRE(clock_gettime(CLOCK_REALTIME, &ts0) == 0, "clock_gettime #1 failed: %s", strerror(errno));
    REQUIRE(nanosleep(&(const struct timespec){ .tv_sec = 0, .tv_nsec = 1000000L }, NULL) == 0,
            "nanosleep failed: %s", strerror(errno));
    REQUIRE(clock_gettime(CLOCK_REALTIME, &ts1) == 0, "clock_gettime #2 failed: %s", strerror(errno));
    REQUIRE(ts1.tv_sec > ts0.tv_sec || (ts1.tv_sec == ts0.tv_sec && ts1.tv_nsec > ts0.tv_nsec),
            "clock did not advance: (%lld,%lld) -> (%lld,%lld)",
            (long long)ts0.tv_sec, (long long)ts0.tv_nsec, (long long)ts1.tv_sec, (long long)ts1.tv_nsec);

    REQUIRE(syscall(SYS_getrandom, rnd, sizeof(rnd), 0) == (long)sizeof(rnd), "getrandom failed: %s", strerror(errno));
    for (i = 0; i < sizeof(rnd); ++i) {
        if (rnd[i] != 0) {
            all_zero = false;
            break;
        }
    }
    REQUIRE(!all_zero, "getrandom returned an all-zero buffer");

    REQUIRE(getrlimit(RLIMIT_NOFILE, &lim) == 0, "getrlimit failed: %s", strerror(errno));
    REQUIRE(lim.rlim_cur == RLIM_INFINITY && lim.rlim_max == RLIM_INFINITY,
            "getrlimit returned cur=%llu max=%llu",
            (unsigned long long)lim.rlim_cur, (unsigned long long)lim.rlim_max);

    memset(&lim2, 0, sizeof(lim2));
    REQUIRE(syscall(SYS_prlimit64, 0, RLIMIT_NOFILE, NULL, &lim2) == 0, "prlimit64 failed: %s", strerror(errno));
    REQUIRE(lim2.rlim_cur == RLIM_INFINITY && lim2.rlim_max == RLIM_INFINITY,
            "prlimit64 returned cur=%llu max=%llu",
            (unsigned long long)lim2.rlim_cur, (unsigned long long)lim2.rlim_max);

    map = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(map != MAP_FAILED, "anonymous mmap failed: %s", strerror(errno));
    memset(map, 0x5a, 8192);
    REQUIRE(((unsigned char*)map)[0] == 0x5a && ((unsigned char*)map)[8191] == 0x5a,
            "anonymous mmap contents did not stick");
    REQUIRE(munmap(map, 8192) == 0, "anonymous munmap failed: %s", strerror(errno));
    map = MAP_FAILED;

    REQUIRE(syscall(SYS_arch_prctl, ARCH_GET_FS, &fs_base) == 0, "arch_prctl(ARCH_GET_FS) failed: %s", strerror(errno));
    REQUIRE(syscall(SYS_arch_prctl, ARCH_SET_FS, fs_base) == 0, "arch_prctl(ARCH_SET_FS same value) failed: %s", strerror(errno));
    REQUIRE(syscall(SYS_arch_prctl, ARCH_GET_FS, &fs_probe) == 0, "arch_prctl(ARCH_GET_FS verify) failed: %s", strerror(errno));
    REQUIRE(fs_probe == fs_base, "FS base changed unexpectedly: 0x%llx -> 0x%llx",
            (unsigned long long)fs_base, (unsigned long long)fs_probe);

    brk_now = syscall(SYS_brk, 0);
    REQUIRE(brk_now > 0, "brk(0) returned %ld", brk_now);
    brk_after = syscall(SYS_brk, brk_now + 4096);
    REQUIRE(brk_after == brk_now + 4096, "growing brk returned %ld from %ld", brk_after, brk_now);
    ((volatile unsigned char*)(uintptr_t)brk_now)[0] = 0xa5;
    REQUIRE(((volatile unsigned char*)(uintptr_t)brk_now)[0] == 0xa5, "grown brk page was not writable");
    brk_restore = syscall(SYS_brk, brk_now);
    REQUIRE(brk_restore == brk_now, "restoring brk returned %ld", brk_restore);

    if (map != MAP_FAILED) {
        munmap(map, 8192);
    }
}

static void test_compat_syscalls(void) {
    static unsigned char altstack_mem[8192];
    stack_t ss;
    stack_t old_ss;
    stack_t probe_ss;
    int pdeathsig = 0;
    int futex_word = 0;
    int status = 0;
    pid_t child = -1;
    char name[16];
    struct timespec timeout = { .tv_sec = 0, .tv_nsec = 1000000L };
    unsigned long robust_head[3] = { 0, 0, 0 };
    void* map = MAP_FAILED;

    memset(&old_ss, 0, sizeof(old_ss));
    REQUIRE(sigaltstack(NULL, &old_ss) == 0, "sigaltstack(query) failed: %s", strerror(errno));
    REQUIRE((old_ss.ss_flags & SS_DISABLE) != 0, "initial alt stack was unexpectedly enabled");

    memset(&ss, 0, sizeof(ss));
    ss.ss_sp = altstack_mem;
    ss.ss_size = sizeof(altstack_mem);
    ss.ss_flags = 0;
    REQUIRE(sigaltstack(&ss, NULL) == 0, "sigaltstack(enable) failed: %s", strerror(errno));

    memset(&probe_ss, 0, sizeof(probe_ss));
    REQUIRE(sigaltstack(NULL, &probe_ss) == 0, "sigaltstack(re-query) failed: %s", strerror(errno));
    REQUIRE((probe_ss.ss_flags & SS_DISABLE) == 0, "alt stack still reported disabled");
    REQUIRE(probe_ss.ss_sp == ss.ss_sp, "alt stack base changed unexpectedly");
    REQUIRE(probe_ss.ss_size == ss.ss_size, "alt stack size changed unexpectedly");

    memset(&ss, 0, sizeof(ss));
    ss.ss_flags = SS_DISABLE;
    REQUIRE(sigaltstack(&ss, NULL) == 0, "sigaltstack(disable) failed: %s", strerror(errno));

    memset(name, 0, sizeof(name));
    REQUIRE(prctl(PR_SET_NAME, (unsigned long)"k-tests", 0, 0, 0) == 0, "prctl(PR_SET_NAME) failed: %s", strerror(errno));
    REQUIRE(prctl(PR_GET_NAME, (unsigned long)name, 0, 0, 0) == 0, "prctl(PR_GET_NAME) failed: %s", strerror(errno));
    REQUIRE(strcmp(name, "k-tests") == 0, "PR_GET_NAME returned %s", name);

    REQUIRE(prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0, "prctl(PR_SET_DUMPABLE,0) failed: %s", strerror(errno));
    REQUIRE(prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0, "prctl(PR_GET_DUMPABLE) did not report 0");
    REQUIRE(prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == 0, "prctl(PR_SET_DUMPABLE,1) failed: %s", strerror(errno));
    REQUIRE(prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 1, "prctl(PR_GET_DUMPABLE) did not report 1");

    REQUIRE(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "prctl(PR_SET_NO_NEW_PRIVS) failed: %s", strerror(errno));
    REQUIRE(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1, "prctl(PR_GET_NO_NEW_PRIVS) did not report 1");

    pdeathsig = 0;
    REQUIRE(prctl(PR_SET_PDEATHSIG, SIGUSR1, 0, 0, 0) == 0, "prctl(PR_SET_PDEATHSIG) failed: %s", strerror(errno));
    REQUIRE(prctl(PR_GET_PDEATHSIG, (unsigned long)&pdeathsig, 0, 0, 0) == 0, "prctl(PR_GET_PDEATHSIG) failed: %s", strerror(errno));
    REQUIRE(pdeathsig == SIGUSR1, "PR_GET_PDEATHSIG returned %d", pdeathsig);

    REQUIRE(syscall(SYS_set_robust_list, robust_head, sizeof(robust_head)) == 0,
            "set_robust_list failed: %s", strerror(errno));

    errno = 0;
    REQUIRE(syscall(SYS_futex, &futex_word, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 1, NULL, NULL, 0) == -1 && errno == EAGAIN,
            "futex WAIT mismatch returned errno=%d", errno);
    REQUIRE(syscall(SYS_futex, &futex_word, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, NULL, NULL, 0) == 0,
            "futex WAKE with no waiters failed: %s", strerror(errno));

    errno = 0;
    REQUIRE(syscall(SYS_futex, &futex_word, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, &timeout, NULL, 0) == -1 && errno == ETIMEDOUT,
            "futex WAIT timeout returned errno=%d", errno);

    child = fork();
    REQUIRE(child >= 0, "fork(futex interrupter) failed: %s", strerror(errno));
    if (child == 0) {
        nanosleep(&(const struct timespec){ .tv_sec = 0, .tv_nsec = 1000000L }, NULL);
        kill(getppid(), SIGUSR1);
        _exit(0);
    }

    errno = 0;
    REQUIRE(syscall(SYS_futex, &futex_word, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0) == -1 && errno == EINTR,
            "futex WAIT interruption returned errno=%d", errno);
    wait_for_exit_code(child, 0);
    child = -1;

    map = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(map != MAP_FAILED, "mmap(read-only anon) failed: %s", strerror(errno));
    errno = 0;
    REQUIRE(syscall(SYS_mprotect, (char*)map + 1, 4096, PROT_READ) == -1 && errno == EINVAL,
            "misaligned mprotect returned errno=%d", errno);
    REQUIRE(mprotect(map, 4096, PROT_NONE) == 0, "mprotect(PROT_NONE) failed: %s", strerror(errno));
    REQUIRE(mprotect(map, 4096, PROT_READ | PROT_WRITE) == 0, "mprotect(PROT_READ|PROT_WRITE) failed: %s", strerror(errno));
    ((volatile unsigned char*)map)[0] = 0x7c;
    REQUIRE(((volatile unsigned char*)map)[0] == 0x7c, "mprotect-upgraded page was not writable");
    REQUIRE(munmap(map, 4096) == 0, "munmap(compat map) failed: %s", strerror(errno));
    map = MAP_FAILED;

    if (map != MAP_FAILED) {
        munmap(map, 4096);
    }
    if (child >= 0) {
        waitpid_retry(child, &status, 0);
    }
}

struct test_case {
    const char* name;
    void (*fn)(void);
};

static const struct test_case g_tests[] = {
    { "identity_and_paths", test_identity_and_paths },
    { "file_io_and_mmap", test_file_io_and_mmap },
    { "pipes_select_and_poll", test_pipes_select_and_poll },
    { "socketpair_and_unix_sockets", test_socketpair_and_unix_sockets },
    { "memory_and_misc", test_memory_and_misc },
    { "compat_syscalls", test_compat_syscalls },
    { "process_wait_and_exec", test_process_wait_and_exec },
    { "process_groups_and_signals", test_process_groups_and_signals },
};

int main(void) {
    size_t i = 0;

    printf("kernel-tests: running %zu test groups\n", sizeof(g_tests) / sizeof(g_tests[0]));

    for (i = 0; i < sizeof(g_tests) / sizeof(g_tests[0]); ++i) {
        int failures_before = g_failures;
        g_current_test = g_tests[i].name;
        printf("[RUN ] %s\n", g_current_test);
        fflush(stdout);
        g_tests[i].fn();
        if (g_failures == failures_before) {
            printf("[PASS] %s\n", g_current_test);
        } else {
            printf("[FAIL] %s\n", g_current_test);
        }
    }

    printf("kernel-tests: %d failures across %d checks\n", g_failures, g_checks);
    return g_failures == 0 ? 0 : 1;
}
