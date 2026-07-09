#define _GNU_SOURCE

#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>

char __kernel_end[1];

void console_write(const char* message) {
    (void)message;
}

void console_printf(const char* format, ...) {
    (void)format;
}

/* Include the allocator so the test can provide its heap mapping directly. */
#include "../kernel/src/kmalloc.c"

int main(void) {
    void* heap = mmap((void*)HEAP_START, HEAP_SIZE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (heap != (void*)HEAP_START) {
        perror("mmap allocator heap");
        return 1;
    }
    g_heap_break = HEAP_START;
    g_initialized = true;

    void* allocation = kmalloc(1u);
    assert(allocation != NULL);
    assert((uintptr_t)allocation % KMALLOC_ALIGN == 0u);

    assert(kmalloc((size_t)UINT32_MAX + 1u) == NULL);
    assert(kmalloc(SIZE_MAX) == NULL);
    assert(krealloc(allocation, SIZE_MAX) == NULL);
    assert(kmalloc_aligned(SIZE_MAX, 4096u) == NULL);

    void* page = kmalloc_aligned(4096u, 4096u);
    assert(page != NULL);
    assert((uintptr_t)page % 4096u == 0u);

    kfree_aligned(page);
    kfree(allocation);
    assert(munmap(heap, HEAP_SIZE) == 0);
    puts("kmalloc host tests passed");
    return 0;
}
