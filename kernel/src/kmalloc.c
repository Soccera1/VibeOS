#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common.h"
#include "console.h"
#include "kmalloc.h"
#include "string.h"

extern char __kernel_end[];
extern char __kernel_start[];

#define HEAP_START ((uintptr_t)__kernel_end)
#define HEAP_SIZE (64u * 1024u * 1024u)
#define HEAP_END (HEAP_START + HEAP_SIZE)
#define MIN_BLOCK_SIZE (sizeof(struct block_header) + 16)

#define BLOCK_HEADER_MAGIC 0xDEADBEEFCAFEBABEULL

struct block_header {
    uint64_t magic;
    size_t size;
    struct block_header* next;
    struct block_header* prev;
    bool free;
};

static struct block_header* g_free_list = NULL;
static bool g_initialized = false;
static uintptr_t g_heap_break;

static struct block_header* get_footer(struct block_header* header) {
    return (struct block_header*)((uintptr_t)header + header->size - sizeof(struct block_header));
}

static void set_footer(struct block_header* header) {
    struct block_header* footer = get_footer(header);
    footer->magic = BLOCK_HEADER_MAGIC;
    footer->size = header->size;
    footer->free = header->free;
}

static struct block_header* request_space(size_t size) {
    size_t total_size = size + sizeof(struct block_header) * 2;
    total_size = (total_size + 15) & ~15;

    if (g_heap_break + total_size > HEAP_END) {
        return NULL;
    }

    struct block_header* block = (struct block_header*)g_heap_break;
    block->magic = BLOCK_HEADER_MAGIC;
    block->size = total_size;
    block->free = true;
    block->next = NULL;
    block->prev = NULL;
    set_footer(block);

    g_heap_break += total_size;

    return block;
}

static void split_block(struct block_header* block, size_t size) {
    size_t remaining = block->size - size - sizeof(struct block_header) * 2;

    if (remaining < MIN_BLOCK_SIZE) {
        return;
    }

    struct block_header* new_block = (struct block_header*)((uintptr_t)block + size);
    new_block->magic = BLOCK_HEADER_MAGIC;
    new_block->size = block->size - size;
    new_block->free = true;
    new_block->next = block->next;
    new_block->prev = block;

    if (block->next) {
        block->next->prev = new_block;
    }

    block->next = new_block;
    block->size = size;
    set_footer(block);
    set_footer(new_block);
}

static void coalesce_forward(struct block_header* block) {
    if (!block->next || !block->next->free) {
        return;
    }

    struct block_header* next = block->next;
    block->size += next->size;
    block->next = next->next;
    if (next->next) {
        next->next->prev = block;
    }
    set_footer(block);
}

static void coalesce_backward(struct block_header* block) {
    if (!block->prev || !block->prev->free) {
        return;
    }

    struct block_header* prev = block->prev;
    prev->size += block->size;
    prev->next = block->next;
    if (block->next) {
        block->next->prev = prev;
    }
    set_footer(prev);
}

static void add_to_free_list(struct block_header* block) {
    block->free = true;
    block->next = g_free_list;
    block->prev = NULL;
    if (g_free_list) {
        g_free_list->prev = block;
    }
    g_free_list = block;
    set_footer(block);
}

static void remove_from_free_list(struct block_header* block) {
    if (block->prev) {
        block->prev->next = block->next;
    } else {
        g_free_list = block->next;
    }
    if (block->next) {
        block->next->prev = block->prev;
    }
}

void kmalloc_init(void) {
    if (g_initialized) {
        return;
    }

    g_heap_break = HEAP_START;
    g_free_list = NULL;
    g_initialized = true;

    console_printf("kmalloc: heap at 0x%lx - 0x%lx (%u MB)\n",
                   (unsigned long)HEAP_START,
                   (unsigned long)HEAP_END,
                   (unsigned)(HEAP_SIZE / (1024u * 1024u)));
}

void* kmalloc(size_t size) {
    if (size == 0) {
        size = 1;
    }

    size = (size + 15) & ~15;
    size_t total_size = size + sizeof(struct block_header) * 2;

    struct block_header* best = NULL;
    struct block_header* current = g_free_list;

    while (current) {
        if (current->magic != BLOCK_HEADER_MAGIC) {
            console_printf("kmalloc: corruption detected at %p\n", (void*)current);
            return NULL;
        }
        if (current->free && current->size >= total_size) {
            if (best == NULL || current->size < best->size) {
                best = current;
                if (current->size == total_size) {
                    break;
                }
            }
        }
        current = current->next;
    }

    if (best) {
        remove_from_free_list(best);
        best->free = false;
        split_block(best, total_size);
        set_footer(best);

        return (void*)((uintptr_t)best + sizeof(struct block_header));
    }

    struct block_header* new_block = request_space(total_size);
    if (!new_block) {
        return NULL;
    }

    new_block->free = false;
    set_footer(new_block);

    return (void*)((uintptr_t)new_block + sizeof(struct block_header));
}

void kfree(void* ptr) {
    if (ptr == NULL) {
        return;
    }

    struct block_header* block = (struct block_header*)((uintptr_t)ptr - sizeof(struct block_header));

    if (block->magic != BLOCK_HEADER_MAGIC) {
        console_printf("kfree: invalid pointer %p\n", ptr);
        return;
    }

    if (block->free) {
        console_printf("kfree: double free detected %p\n", ptr);
        return;
    }

    block->free = true;
    set_footer(block);

    coalesce_forward(block);
    coalesce_backward(block);

    add_to_free_list(block);
}

void* krealloc(void* ptr, size_t new_size) {
    if (ptr == NULL) {
        return kmalloc(new_size);
    }
    if (new_size == 0) {
        kfree(ptr);
        return NULL;
    }

    struct block_header* block = (struct block_header*)((uintptr_t)ptr - sizeof(struct block_header));

    if (block->magic != BLOCK_HEADER_MAGIC) {
        return NULL;
    }

    new_size = (new_size + 15) & ~15;
    size_t total_new = new_size + sizeof(struct block_header) * 2;

    if (block->size >= total_new) {
        return ptr;
    }

    void* new_ptr = kmalloc(new_size);
    if (new_ptr == NULL) {
        return NULL;
    }

    size_t usable_old = block->size - sizeof(struct block_header) * 2;
    memcpy(new_ptr, ptr, usable_old < new_size ? usable_old : new_size);

    kfree(ptr);
    return new_ptr;
}

void* kmalloc_aligned(size_t size, size_t alignment) {
    if (alignment == 0 || (alignment & (alignment - 1)) != 0) {
        return NULL;
    }

    size_t total = size + alignment + sizeof(void*);
    void* raw = kmalloc(total);
    if (raw == NULL) {
        return NULL;
    }

    uintptr_t aligned = (uintptr_t)raw + sizeof(void*);
    aligned = (aligned + alignment - 1) & ~(alignment - 1);

    ((void**)aligned)[-1] = raw;

    return (void*)aligned;
}