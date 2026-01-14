#ifndef _MALLOC_H
#define _MALLOC_H

#include <stddef.h>
#include <alloca.h>

void *malloc(size_t size);
void free(void *ptr);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);

#endif
