#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

void kmalloc_init(void);
void* kmalloc(size_t size);
void kfree(void* ptr);
void* krealloc(void* ptr, size_t new_size);

void* kmalloc_aligned(size_t size, size_t alignment);
void kfree_aligned(void* ptr);
bool kmalloc_owns(const void* ptr);
