#ifndef PMM_H
#define PMM_H

#include <stdint.h>

void pmm_init(uint32_t mem_size);
void pmm_free_page(uint32_t page_addr);
void pmm_free_region(uint32_t base, uint32_t size);
uint32_t pmm_alloc_page();

#endif
