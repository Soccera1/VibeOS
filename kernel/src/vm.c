#include "vm.h"

#include <stddef.h>
#include <stdint.h>

#include "io.h"
#include "kmalloc.h"
#include "string.h"

#define VM_PTE_PRESENT 0x001ull
#define VM_PTE_RW 0x002ull
#define VM_PTE_USER 0x004ull
#define VM_PTE_PS 0x080ull

#define VM_PT_ENTRIES 512u
#define VM_IDENTITY_LIMIT (1ull << 30)

static uint64_t* g_kernel_pml4;
static uint64_t* g_kernel_pdpt;
static uint64_t* g_kernel_pd;
static const struct vm_space* g_active_space;

static void* alloc_page_table(void) {
    void* page = kmalloc_aligned(VM_PAGE_SIZE, VM_PAGE_SIZE);
    if (page != NULL) {
        memset(page, 0, VM_PAGE_SIZE);
    }
    return page;
}

static void flush_if_active(const struct vm_space* space, uint64_t addr) {
    if (space != g_active_space) {
        return;
    }

    if (addr == UINT64_MAX) {
        write_cr3((uint64_t)(uintptr_t)space->pml4);
        return;
    }

    invlpg((void*)(uintptr_t)addr);
}

static int ensure_mapping_capacity(struct vm_space* space, size_t need) {
    if (need <= space->mapping_cap) {
        return 0;
    }

    size_t next_cap = (space->mapping_cap == 0) ? 16 : space->mapping_cap * 2;
    while (next_cap < need) {
        next_cap *= 2;
    }

    struct vm_mapping* resized = krealloc(space->mappings, next_cap * sizeof(*resized));
    if (resized == NULL) {
        return -1;
    }

    space->mappings = resized;
    space->mapping_cap = next_cap;
    return 0;
}

static int find_mapping_index(const struct vm_space* space, uint64_t page_addr) {
    for (size_t i = 0; i < space->mapping_count; ++i) {
        if (space->mappings[i].vaddr == page_addr) {
            return (int)i;
        }
    }
    return -1;
}

static bool user_page_valid(uint64_t page_addr) {
    return page_addr >= VM_USER_BASE && page_addr < VM_USER_LIMIT;
}

static int ensure_pt(struct vm_space* space, size_t pd_index) {
    if (space->pts[pd_index] != NULL) {
        return 0;
    }

    uint64_t* pt = alloc_page_table();
    if (pt == NULL) {
        return -1;
    }

    uint64_t base = ((uint64_t)pd_index) << 21;
    for (size_t i = 0; i < VM_PT_ENTRIES; ++i) {
        uint64_t addr = base + (((uint64_t)i) << 12);
        pt[i] = addr | VM_PTE_PRESENT | VM_PTE_RW;
    }

    space->pts[pd_index] = pt;
    space->pd[pd_index] = ((uint64_t)(uintptr_t)pt) | VM_PTE_PRESENT | VM_PTE_RW | VM_PTE_USER;
    flush_if_active(space, UINT64_MAX);
    return 0;
}

static int map_user_page(struct vm_space* space, uint64_t page_addr, uint8_t* backing_page, bool replace_existing) {
    if (!user_page_valid(page_addr) || backing_page == NULL) {
        return -1;
    }

    size_t pd_index = (size_t)((page_addr >> 21) & 0x1FFu);
    size_t pt_index = (size_t)((page_addr >> 12) & 0x1FFu);
    if (ensure_pt(space, pd_index) != 0) {
        return -1;
    }

    int existing = find_mapping_index(space, page_addr);
    if (existing >= 0) {
        if (!replace_existing) {
            return 0;
        }
        if (space->mappings[existing].page != NULL) {
            kfree_aligned(space->mappings[existing].page);
        }
        space->mappings[existing].page = backing_page;
    } else {
        if (ensure_mapping_capacity(space, space->mapping_count + 1) != 0) {
            return -1;
        }
        space->mappings[space->mapping_count].vaddr = page_addr;
        space->mappings[space->mapping_count].page = backing_page;
        space->mapping_count++;
    }

    space->pts[pd_index][pt_index] = ((uint64_t)(uintptr_t)backing_page) | VM_PTE_PRESENT | VM_PTE_RW | VM_PTE_USER;
    flush_if_active(space, page_addr);
    return 0;
}

static int alloc_and_map_zero_page(struct vm_space* space, uint64_t page_addr, bool replace_existing) {
    uint8_t* page = kmalloc_aligned(VM_PAGE_SIZE, VM_PAGE_SIZE);
    if (page == NULL) {
        return -1;
    }

    memset(page, 0, VM_PAGE_SIZE);
    if (map_user_page(space, page_addr, page, replace_existing) != 0) {
        kfree_aligned(page);
        return -1;
    }
    return 0;
}

static uint8_t* mapping_page_for(const struct vm_space* space, uint64_t addr) {
    uint64_t page_addr = addr & VM_PAGE_MASK;
    int index = find_mapping_index(space, page_addr);
    if (index < 0) {
        return NULL;
    }
    return space->mappings[index].page;
}

static void restore_identity_mapping(struct vm_space* space, uint64_t page_addr) {
    size_t pd_index = (size_t)((page_addr >> 21) & 0x1FFu);
    size_t pt_index = (size_t)((page_addr >> 12) & 0x1FFu);
    if (space->pts[pd_index] == NULL) {
        return;
    }

    space->pts[pd_index][pt_index] = page_addr | VM_PTE_PRESENT | VM_PTE_RW;
    flush_if_active(space, page_addr);
}

void vm_init(void) {
    g_kernel_pml4 = alloc_page_table();
    g_kernel_pdpt = alloc_page_table();
    g_kernel_pd = alloc_page_table();
    if (g_kernel_pml4 == NULL || g_kernel_pdpt == NULL || g_kernel_pd == NULL) {
        for (;;) {
            hlt();
        }
    }

    g_kernel_pml4[0] = ((uint64_t)(uintptr_t)g_kernel_pdpt) | VM_PTE_PRESENT | VM_PTE_RW | VM_PTE_USER;
    g_kernel_pdpt[0] = ((uint64_t)(uintptr_t)g_kernel_pd) | VM_PTE_PRESENT | VM_PTE_RW | VM_PTE_USER;

    for (size_t i = 0; i < VM_PT_ENTRIES; ++i) {
        uint64_t addr = ((uint64_t)i) << 21;
        if (addr >= VM_IDENTITY_LIMIT) {
            break;
        }
        g_kernel_pd[i] = addr | VM_PTE_PRESENT | VM_PTE_RW | VM_PTE_PS;
    }

    g_active_space = NULL;
}

int vm_space_init(struct vm_space* space) {
    if (space == NULL) {
        return -1;
    }

    memset(space, 0, sizeof(*space));
    space->pml4 = alloc_page_table();
    space->pdpt = alloc_page_table();
    space->pd = alloc_page_table();
    if (space->pml4 == NULL || space->pdpt == NULL || space->pd == NULL) {
        vm_space_destroy(space);
        return -1;
    }

    memcpy(space->pml4, g_kernel_pml4, VM_PAGE_SIZE);
    memcpy(space->pdpt, g_kernel_pdpt, VM_PAGE_SIZE);
    memcpy(space->pd, g_kernel_pd, VM_PAGE_SIZE);
    space->pml4[0] = ((uint64_t)(uintptr_t)space->pdpt) | VM_PTE_PRESENT | VM_PTE_RW | VM_PTE_USER;
    space->pdpt[0] = ((uint64_t)(uintptr_t)space->pd) | VM_PTE_PRESENT | VM_PTE_RW | VM_PTE_USER;
    return 0;
}

void vm_space_activate(const struct vm_space* space) {
    if (space == NULL || space->pml4 == NULL) {
        return;
    }

    g_active_space = space;
    write_cr3((uint64_t)(uintptr_t)space->pml4);
}

void vm_space_reset_user(struct vm_space* space) {
    if (space == NULL) {
        return;
    }

    for (size_t i = 0; i < space->mapping_count; ++i) {
        uint64_t page_addr = space->mappings[i].vaddr;
        if (space->mappings[i].page != NULL) {
            kfree_aligned(space->mappings[i].page);
        }
        restore_identity_mapping(space, page_addr);
    }

    if (space->mappings != NULL) {
        kfree(space->mappings);
        space->mappings = NULL;
    }
    space->mapping_count = 0;
    space->mapping_cap = 0;
}

void vm_space_destroy(struct vm_space* space) {
    if (space == NULL) {
        return;
    }

    vm_space_reset_user(space);
    for (size_t i = 0; i < VM_PT_ENTRIES; ++i) {
        if (space->pts[i] != NULL) {
            kfree_aligned(space->pts[i]);
            space->pts[i] = NULL;
        }
    }

    if (space->pml4 != NULL) {
        kfree_aligned(space->pml4);
        space->pml4 = NULL;
    }
    if (space->pdpt != NULL) {
        kfree_aligned(space->pdpt);
        space->pdpt = NULL;
    }
    if (space->pd != NULL) {
        kfree_aligned(space->pd);
        space->pd = NULL;
    }
}

int vm_space_clone(struct vm_space* dst, const struct vm_space* src) {
    if (dst == NULL || src == NULL) {
        return -1;
    }

    if (vm_space_init(dst) != 0) {
        return -1;
    }

    for (size_t i = 0; i < src->mapping_count; ++i) {
        uint8_t* page = kmalloc_aligned(VM_PAGE_SIZE, VM_PAGE_SIZE);
        if (page == NULL) {
            vm_space_destroy(dst);
            return -1;
        }

        memcpy(page, src->mappings[i].page, VM_PAGE_SIZE);
        if (map_user_page(dst, src->mappings[i].vaddr, page, false) != 0) {
            kfree_aligned(page);
            vm_space_destroy(dst);
            return -1;
        }
    }

    return 0;
}

int vm_space_map_zero(struct vm_space* space, uint64_t addr, size_t len) {
    if (space == NULL) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }

    uint64_t start = addr & VM_PAGE_MASK;
    uint64_t end = (addr + len + VM_PAGE_SIZE - 1ull) & VM_PAGE_MASK;
    if (end < start || start < VM_USER_BASE || end > VM_USER_LIMIT) {
        return -1;
    }

    for (uint64_t page_addr = start; page_addr < end; page_addr += VM_PAGE_SIZE) {
        if (find_mapping_index(space, page_addr) >= 0) {
            continue;
        }
        if (alloc_and_map_zero_page(space, page_addr, false) != 0) {
            return -1;
        }
    }

    return 0;
}

int vm_space_write(struct vm_space* space, uint64_t addr, const void* src, size_t len) {
    if (space == NULL || (src == NULL && len != 0)) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }
    if (addr < VM_USER_BASE || addr + len < addr || addr + len > VM_USER_LIMIT) {
        return -1;
    }

    const uint8_t* in = src;
    uint64_t cursor = addr;
    size_t remaining = len;
    while (remaining > 0) {
        uint8_t* page = mapping_page_for(space, cursor);
        if (page == NULL) {
            return -1;
        }

        size_t page_off = (size_t)(cursor & (VM_PAGE_SIZE - 1ull));
        size_t chunk = VM_PAGE_SIZE - page_off;
        if (chunk > remaining) {
            chunk = remaining;
        }

        memcpy(page + page_off, in, chunk);
        cursor += chunk;
        in += chunk;
        remaining -= chunk;
    }

    return 0;
}

int vm_space_zero(struct vm_space* space, uint64_t addr, size_t len) {
    if (space == NULL) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }
    if (addr < VM_USER_BASE || addr + len < addr || addr + len > VM_USER_LIMIT) {
        return -1;
    }

    uint64_t cursor = addr;
    size_t remaining = len;
    while (remaining > 0) {
        uint8_t* page = mapping_page_for(space, cursor);
        if (page == NULL) {
            return -1;
        }

        size_t page_off = (size_t)(cursor & (VM_PAGE_SIZE - 1ull));
        size_t chunk = VM_PAGE_SIZE - page_off;
        if (chunk > remaining) {
            chunk = remaining;
        }

        memset(page + page_off, 0, chunk);
        cursor += chunk;
        remaining -= chunk;
    }

    return 0;
}

int vm_space_unmap(struct vm_space* space, uint64_t addr, size_t len) {
    if (space == NULL) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }

    uint64_t start = addr & VM_PAGE_MASK;
    uint64_t end = (addr + len + VM_PAGE_SIZE - 1ull) & VM_PAGE_MASK;
    if (end < start || start < VM_USER_BASE || end > VM_USER_LIMIT) {
        return -1;
    }

    for (uint64_t page_addr = start; page_addr < end; page_addr += VM_PAGE_SIZE) {
        int index = find_mapping_index(space, page_addr);
        if (index < 0) {
            continue;
        }

        if (space->mappings[index].page != NULL) {
            kfree_aligned(space->mappings[index].page);
        }
        restore_identity_mapping(space, page_addr);

        size_t tail = space->mapping_count - ((size_t)index + 1);
        if (tail > 0) {
            memmove(&space->mappings[index], &space->mappings[index + 1], tail * sizeof(space->mappings[0]));
        }
        space->mapping_count--;
    }

    if (space->mapping_count == 0 && space->mappings != NULL) {
        kfree(space->mappings);
        space->mappings = NULL;
        space->mapping_cap = 0;
    }

    return 0;
}

bool vm_space_range_mapped(const struct vm_space* space, uint64_t addr, size_t len) {
    if (space == NULL) {
        return false;
    }
    if (len == 0) {
        return true;
    }
    if (addr < VM_USER_BASE || addr + len < addr || addr + len > VM_USER_LIMIT) {
        return false;
    }

    uint64_t start = addr & VM_PAGE_MASK;
    uint64_t end = (addr + len + VM_PAGE_SIZE - 1ull) & VM_PAGE_MASK;
    for (uint64_t page_addr = start; page_addr < end; page_addr += VM_PAGE_SIZE) {
        if (find_mapping_index(space, page_addr) < 0) {
            return false;
        }
    }
    return true;
}
