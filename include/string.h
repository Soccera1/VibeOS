#ifndef _STRING_H
#define _STRING_H

#include <stddef.h>

void* memset(void* s, int c, size_t n);
void* memcpy(void* dest, const void* src, size_t n);
void* mempcpy(void* dest, const void* src, size_t n);
void* memmove(void* dest, const void* src, size_t n);
size_t strlen(const char* s);
int strcmp(const char* s1, const char* s2);
int strncmp(const char* s1, const char* s2, size_t n);
char* strcpy(char* dest, const char* src);
char* strncpy(char* dest, const char* src, size_t n);
char* stpncpy(char* dest, const char* src, size_t n);
char* strchr(const char* s, int c);
char* strrchr(const char* s, int c);
char* strpbrk(const char* s, const char* accept);
char* strtok_r(char* str, const char* delim, char** saveptr);
char* strdup(const char* s);
int memcmp(const void* s1, const void* s2, size_t n);
char* strerror(int errnum);
char* strstr(const char* haystack, const char* needle);
char* stpcpy(char* dest, const char* src);
int strcasecmp(const char* s1, const char* s2);
int strncasecmp(const char* s1, const char* s2, size_t n);
size_t strspn(const char *s, const char *accept);
size_t strcspn(const char *s, const char *reject);
char *strchrnul(const char *s, int c);

#endif