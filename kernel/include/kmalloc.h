#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

// reserved_end covers boot modules and Multiboot information still in use.
void kmalloc_init(uintptr_t reserved_end);
void* kmalloc(size_t size);
void kfree(void* ptr);
void* krealloc(void* ptr, size_t new_size);

void* kmalloc_aligned(size_t size, size_t alignment);
void kfree_aligned(void* ptr);
bool kmalloc_owns(const void* ptr);
