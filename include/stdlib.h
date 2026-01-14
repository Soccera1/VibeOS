#ifndef _STDLIB_H
#define _STDLIB_H

#include <stddef.h>
#include <alloca.h>
#include <user/libc.h>

void *malloc(size_t size);
void *realloc(void *ptr, size_t size);
void *calloc(size_t nmemb, size_t size);
void free(void *ptr);
void exit(int status);
char *getenv(const char *name);
int putenv(char *string);
int setenv(const char *name, const char *value, int overwrite);
int unsetenv(const char *name);
int clearenv(void);
int atoi(const char *nptr);
void srand(unsigned int seed);
int rand(void);
void qsort(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *));
void *bsearch(const void *key, const void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *));
int mkstemp(char *template);
char *realpath(const char *path, char *resolved_path);
long strtol(const char *nptr, char **endptr, int base);
unsigned long strtoul(const char *nptr, char **endptr, int base);
long long strtoll(const char *nptr, char **endptr, int base);
unsigned long long strtoull(const char *nptr, char **endptr, int base);

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#endif
