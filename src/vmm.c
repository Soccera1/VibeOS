#include <kernel/vmm.h>
#include <kernel/debugcon.h>
#include <string.h>

static uint32_t kernel_page_directory[1024] __attribute__((aligned(4096)));
static uint32_t page_tables[64][1024] __attribute__((aligned(4096)));
static int next_free_table = 0;

void vmm_map(uint32_t virtual_addr, uint32_t physical_addr, uint32_t flags) {
    uint32_t dir_idx = virtual_addr >> 22;
    uint32_t tbl_idx = (virtual_addr >> 12) & 0x3FF;

    if (!(kernel_page_directory[dir_idx] & PAGE_PRESENT)) {
        if (next_free_table >= 64) {
            print_debugcon("VMM: Out of page tables!\n");
            return;
        }
        uint32_t tbl_phys = (uint32_t)page_tables[next_free_table++];
        memset((void*)tbl_phys, 0, 4096);
        kernel_page_directory[dir_idx] = tbl_phys | PAGE_PRESENT | PAGE_RW | (flags & PAGE_USER);
    } else {
        if (flags & PAGE_USER) {
            kernel_page_directory[dir_idx] |= PAGE_USER;
        }
    }

    uint32_t *table = (uint32_t*)(kernel_page_directory[dir_idx] & 0xFFFFF000);
    table[tbl_idx] = (physical_addr & 0xFFFFF000) | flags;
    
    asm volatile("invlpg (%0)" :: "r"(virtual_addr) : "memory");
}

static void vmm_identity_map(uint32_t start, uint32_t size, uint32_t flags) {
    uint32_t end = start + size;
    uint32_t start_page = start & 0xFFFFF000;
    uint32_t end_page = (end + PAGE_SIZE - 1) & 0xFFFFF000;

    for (uint32_t addr = start_page; addr < end_page; addr += PAGE_SIZE) {
        vmm_map(addr, addr, flags);
    }
}

void vmm_init(uint32_t framebuffer_addr, uint32_t framebuffer_size, uint32_t initrd_addr, uint32_t initrd_size) {
    memset(kernel_page_directory, 0, sizeof(kernel_page_directory));
    next_free_table = 0;

    // Identity map kernel and FB as supervisor
    vmm_identity_map(0, 0x800000, PAGE_PRESENT | PAGE_RW);
    vmm_identity_map(framebuffer_addr, framebuffer_size, PAGE_PRESENT | PAGE_RW);

    // Map initrd
    if (initrd_size > 0) {
        vmm_identity_map(initrd_addr, initrd_size, PAGE_PRESENT | PAGE_RW);
    }

    asm volatile("mov %0, %%cr3" :: "r"(kernel_page_directory));

    uint32_t cr0;
    asm volatile("mov %%cr0, %0" : "=r"(cr0));
    cr0 |= 0x80000000;
    asm volatile("mov %0, %%cr0" :: "r"(cr0));

    print_debugcon("VMM: Paging Enabled\n");
}
