#ifndef VMM_H
#define VMM_H

#include <stdint.h>
#include <stddef.h>

#define PAGE_SIZE 4096

// Page Table Entry flags
#define PAGE_PRESENT  0x1
#define PAGE_RW       0x2
#define PAGE_USER     0x4
#define PAGE_WRITETHROUGH 0x8
#define PAGE_NOCACHE  0x10

void vmm_init(uint32_t framebuffer_addr, uint32_t framebuffer_size, uint32_t initrd_addr, uint32_t initrd_size);
void vmm_map(uint32_t virtual_addr, uint32_t physical_addr, uint32_t flags);

#endif
