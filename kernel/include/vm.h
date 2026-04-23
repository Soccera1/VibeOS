#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VM_PAGE_SIZE 0x1000ull
#define VM_PAGE_MASK (~(VM_PAGE_SIZE - 1ull))

#define VM_USER_BASE 0x00400000ull
#define VM_USER_STACK_TOP 0x08000000ull
#define VM_USER_STACK_SIZE 0x00200000ull
#define VM_USER_STACK_BASE (VM_USER_STACK_TOP - VM_USER_STACK_SIZE)
#define VM_USER_BRK_BASE 0x09000000ull
#define VM_USER_MMAP_BASE 0x0C000000ull
#define VM_USER_MMAP_LIMIT 0x0F000000ull
#define VM_USER_ELF_LIMIT 0x20000000ull
#define VM_USER_LIMIT 0x40000000ull

#define VM_PROT_NONE 0u
#define VM_PROT_READ 0x1u
#define VM_PROT_WRITE 0x2u
#define VM_PROT_EXEC 0x4u

struct vm_mapping {
    uint64_t vaddr;
    uint8_t* page;
    bool owned;
    uint32_t prot;
};

struct vm_space {
    uint64_t* pml4;
    uint64_t* pdpt;
    uint64_t* pd;
    uint64_t* pts[512];
    struct vm_mapping* mappings;
    size_t mapping_count;
    size_t mapping_cap;
};

void vm_init(void);

int vm_space_init(struct vm_space* space);
void vm_space_destroy(struct vm_space* space);
void vm_space_activate(const struct vm_space* space);
void vm_space_reset_user(struct vm_space* space);
int vm_space_clone(struct vm_space* dst, const struct vm_space* src);
int vm_space_map_zero(struct vm_space* space, uint64_t addr, size_t len, uint32_t prot);
int vm_space_map_physical(struct vm_space* space, uint64_t addr, uint64_t phys_addr, size_t len, uint32_t prot);
int vm_space_write(struct vm_space* space, uint64_t addr, const void* src, size_t len);
int vm_space_zero(struct vm_space* space, uint64_t addr, size_t len);
int vm_space_unmap(struct vm_space* space, uint64_t addr, size_t len);
int vm_space_mprotect(struct vm_space* space, uint64_t addr, size_t len, uint32_t prot);
bool vm_space_range_mapped(const struct vm_space* space, uint64_t addr, size_t len);
void* vm_space_host_ptr(const struct vm_space* space, uint64_t addr, size_t len);
