#include "libc.h"
#include <vibeos/syscall.h>

extern int main();

void _start() {
    int res = main();
    exit(res);
}

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

int exec(const char* filename) {
    return syscall(SYS_EXEC, (int)filename, 0, 0);
}

int ls() {
    return syscall(SYS_LS, 0, 0, 0);
}

void putchar(char c) {
    write(1, &c, 1);
}

void puts(const char* s) {
    write(1, s, strlen(s));
}

size_t strlen(const char* s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

int strcmp(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++; s2++;
    }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}