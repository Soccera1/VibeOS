#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int parse_int(const char* text) {
    char* end = NULL;
    long value = strtol(text, &end, 10);
    if (text == NULL || *text == '\0' || end == NULL || *end != '\0') {
        fprintf(stderr, "invalid integer: %s\n", text == NULL ? "(null)" : text);
        return -1;
    }
    return (int)value;
}

static int cmd_print_env(int argc, char** argv) {
    const char* env = getenv("KERNEL_TEST_ENV");
    printf("argc=%d argv1=%s argv2=%s env=%s\n",
           argc,
           argc > 1 ? argv[1] : "(missing)",
           argc > 2 ? argv[2] : "(missing)",
           env != NULL ? env : "(null)");
    return (env != NULL && strcmp(env, "present") == 0) ? 0 : 7;
}

static int cmd_check_fd_closed(const char* fd_text) {
    int fd = parse_int(fd_text);
    if (fd < 0) {
        return 8;
    }

    errno = 0;
    if (fcntl(fd, F_GETFD) == -1 && errno == EBADF) {
        return 0;
    }

    fprintf(stderr, "fd %d was still open across exec\n", fd);
    return 9;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <print-env|check-fd-closed> [args...]\n", argv[0]);
        return 64;
    }

    if (strcmp(argv[1], "print-env") == 0) {
        return cmd_print_env(argc, argv);
    }
    if (strcmp(argv[1], "check-fd-closed") == 0) {
        if (argc < 3) {
            fprintf(stderr, "check-fd-closed requires an fd number\n");
            return 65;
        }
        return cmd_check_fd_closed(argv[2]);
    }

    fprintf(stderr, "unknown subcommand: %s\n", argv[1]);
    return 66;
}
