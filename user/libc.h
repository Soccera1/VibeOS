#ifndef _LIBC_H
#define _LIBC_H

#include <stdint.h>
#include <stddef.h>

int write(int fd, const void* buf, size_t count);
int read(int fd, void* buf, size_t count);
void exit(int status);
int exec(const char* filename);
int ls();

// String utils (userland version)
int strcmp(const char* s1, const char* s2);
size_t strlen(const char* s);
void putchar(char c);
void puts(const char* s);

#endif
