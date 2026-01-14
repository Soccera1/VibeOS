#include <stdint.h>
#include <string.h>

#define PAGE_SIZE 4096
#define BITMAP_SIZE 32768 // Supports up to 1GB of RAM

uint32_t pmm_bitmap[BITMAP_SIZE];
uint32_t last_free_page = 0;

void pmm_init(uint32_t mem_size) {
    memset(pmm_bitmap, 0xFF, sizeof(pmm_bitmap)); // Mark all as used initially
}

void pmm_free_page(uint32_t page_addr) {
    uint32_t frame = page_addr / PAGE_SIZE;
    uint32_t idx = frame / 32;
    uint32_t off = frame % 32;
    pmm_bitmap[idx] &= ~(1 << off);
}

void pmm_free_region(uint32_t base, uint32_t size) {
    uint32_t align_base = (base + PAGE_SIZE - 1) & 0xFFFFF000;
    uint32_t align_end = (base + size) & 0xFFFFF000;

    for (uint32_t addr = align_base; addr < align_end; addr += PAGE_SIZE) {
        pmm_free_page(addr);
    }
}

uint32_t pmm_alloc_page() {
    for (uint32_t i = 0; i < BITMAP_SIZE; i++) {
        if (pmm_bitmap[i] != 0xFFFFFFFF) {
            for (int j = 0; j < 32; j++) {
                if (!(pmm_bitmap[i] & (1 << j))) {
                    pmm_bitmap[i] |= (1 << j);
                    return (i * 32 + j) * PAGE_SIZE;
                }
            }
        }
    }
    return 0; // Out of memory
}
