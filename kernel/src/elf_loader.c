#include "elf_loader.h"

#include <stdint.h>

#include "string.h"
#include "vm.h"

#define ELFCLASS64 2u
#define ELFDATA2LSB 1u
#define EV_CURRENT 1u
#define EM_X86_64 62u
#define PT_LOAD 1u
#define PT_INTERP 3u
#define PT_PHDR 6u
#define PF_X 0x1u
#define PF_W 0x2u
#define PF_R 0x4u
#define ELF_MAX_PHNUM 256u
#define ELF_DEFAULT_DYN_BASE 0x01000000ull

struct elf64_ehdr {
    uint8_t e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} __attribute__((packed));

struct elf64_phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} __attribute__((packed));

static bool add_overflows_u64(uint64_t left, uint64_t right, uint64_t* out) {
    *out = left + right;
    return *out < left;
}

static bool range_in_file(uint64_t offset, uint64_t length, size_t file_size) {
    return offset <= (uint64_t)file_size && length <= (uint64_t)file_size - offset;
}

static bool is_power_of_two(uint64_t value) {
    return value != 0 && (value & (value - 1u)) == 0;
}

static uint64_t page_down(uint64_t value) {
    return value & VM_PAGE_MASK;
}

static bool page_up(uint64_t value, uint64_t* out) {
    uint64_t rounded;
    if (add_overflows_u64(value, VM_PAGE_SIZE - 1u, &rounded)) {
        return false;
    }
    *out = rounded & VM_PAGE_MASK;
    return true;
}

static uint32_t segment_prot(uint32_t flags) {
    uint32_t prot = VM_PROT_NONE;
    if ((flags & PF_R) != 0u) {
        prot |= VM_PROT_READ;
    }
    if ((flags & PF_W) != 0u) {
        prot |= VM_PROT_READ | VM_PROT_WRITE;
    }
    if ((flags & PF_X) != 0u) {
        prot |= VM_PROT_EXEC;
    }
    return prot;
}

static bool load_segment_bounds(const struct elf64_phdr* ph, uint64_t bias,
                                uint64_t* start_out, uint64_t* end_out) {
    uint64_t start;
    uint64_t raw_end;
    uint64_t end;
    if (add_overflows_u64(ph->p_vaddr, bias, &start) ||
        add_overflows_u64(start, ph->p_memsz, &raw_end) || !page_up(raw_end, &end)) {
        return false;
    }
    *start_out = page_down(start);
    *end_out = end;
    return true;
}

static uint32_t page_prot(const struct elf64_phdr* phdrs, uint16_t phnum,
                          uint64_t bias, uint64_t page) {
    uint32_t prot = VM_PROT_NONE;
    for (uint16_t i = 0; i < phnum; ++i) {
        if (phdrs[i].p_type != PT_LOAD || phdrs[i].p_memsz == 0) {
            continue;
        }
        uint64_t start;
        uint64_t end;
        if (load_segment_bounds(&phdrs[i], bias, &start, &end) && page >= start && page < end) {
            prot |= segment_prot(phdrs[i].p_flags);
        }
    }
    return prot;
}

int elf_load_image(struct vm_space* space, const uint8_t* image, size_t image_size,
                   uint64_t et_dyn_base, struct elf_image_info* out) {
    if (space == NULL || image == NULL || out == NULL || image_size < sizeof(struct elf64_ehdr)) {
        return ELF_LOAD_INVALID;
    }
    memset(out, 0, sizeof(*out));

    const struct elf64_ehdr* eh = (const struct elf64_ehdr*)image;
    if (eh->e_ident[0] != 0x7f || eh->e_ident[1] != 'E' || eh->e_ident[2] != 'L' || eh->e_ident[3] != 'F' ||
        eh->e_ident[4] != ELFCLASS64 || eh->e_ident[5] != ELFDATA2LSB || eh->e_ident[6] != EV_CURRENT ||
        eh->e_machine != EM_X86_64 || eh->e_version != EV_CURRENT || eh->e_ehsize != sizeof(*eh) ||
        (eh->e_type != ELF_ET_EXEC && eh->e_type != ELF_ET_DYN) || eh->e_phnum == 0 ||
        eh->e_phnum > ELF_MAX_PHNUM || eh->e_phentsize != sizeof(struct elf64_phdr)) {
        return ELF_LOAD_INVALID;
    }

    uint64_t phdr_size = (uint64_t)eh->e_phnum * sizeof(struct elf64_phdr);
    if (!range_in_file(eh->e_phoff, phdr_size, image_size)) {
        return ELF_LOAD_INVALID;
    }
    const struct elf64_phdr* ph = (const struct elf64_phdr*)(image + eh->e_phoff);

    uint64_t min_vaddr = UINT64_MAX;
    uint64_t max_vaddr = 0;
    for (uint16_t i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type == PT_INTERP) {
            if (out->has_interp || ph[i].p_filesz < 2 || ph[i].p_filesz > sizeof(out->interp_path) ||
                !range_in_file(ph[i].p_offset, ph[i].p_filesz, image_size)) {
                return ELF_LOAD_INVALID;
            }
            const char* path = (const char*)(image + ph[i].p_offset);
            if (path[0] != '/' || path[ph[i].p_filesz - 1u] != '\0') {
                return ELF_LOAD_INVALID;
            }
            for (uint64_t j = 0; j + 1u < ph[i].p_filesz; ++j) {
                if (path[j] == '\0') {
                    return ELF_LOAD_INVALID;
                }
            }
            memcpy(out->interp_path, path, (size_t)ph[i].p_filesz);
            out->has_interp = true;
            continue;
        }
        if (ph[i].p_type != PT_LOAD) {
            continue;
        }
        if (ph[i].p_filesz > ph[i].p_memsz || !range_in_file(ph[i].p_offset, ph[i].p_filesz, image_size) ||
            (ph[i].p_align > 1u && (!is_power_of_two(ph[i].p_align) ||
                                   (ph[i].p_vaddr & (ph[i].p_align - 1u)) !=
                                       (ph[i].p_offset & (ph[i].p_align - 1u))))) {
            return ELF_LOAD_INVALID;
        }
        if (ph[i].p_memsz == 0) {
            continue;
        }
        uint64_t raw_end;
        uint64_t end;
        if (add_overflows_u64(ph[i].p_vaddr, ph[i].p_memsz, &raw_end) || !page_up(raw_end, &end)) {
            return ELF_LOAD_INVALID;
        }
        uint64_t start = page_down(ph[i].p_vaddr);
        if (start < min_vaddr) {
            min_vaddr = start;
        }
        if (end > max_vaddr) {
            max_vaddr = end;
        }
    }
    if (min_vaddr == UINT64_MAX || max_vaddr <= min_vaddr) {
        return ELF_LOAD_INVALID;
    }

    uint64_t bias = 0;
    if (eh->e_type == ELF_ET_DYN) {
        uint64_t base = page_down(et_dyn_base != 0 ? et_dyn_base : ELF_DEFAULT_DYN_BASE);
        if (base < min_vaddr) {
            return ELF_LOAD_INVALID;
        }
        bias = base - min_vaddr;
    } else if (et_dyn_base != 0) {
        return ELF_LOAD_INVALID;
    }

    uint64_t image_start;
    uint64_t image_end;
    if (add_overflows_u64(min_vaddr, bias, &image_start) || add_overflows_u64(max_vaddr, bias, &image_end) ||
        image_start < VM_USER_BASE || image_end > VM_USER_ELF_LIMIT || image_end <= image_start ||
        (image_start < VM_USER_STACK_TOP && image_end > VM_USER_STACK_BASE)) {
        return ELF_LOAD_INVALID;
    }

    uint64_t entry;
    if (add_overflows_u64(eh->e_entry, bias, &entry)) {
        return ELF_LOAD_INVALID;
    }
    bool entry_is_executable = false;
    for (uint16_t i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type != PT_LOAD || ph[i].p_memsz == 0 || (ph[i].p_flags & PF_X) == 0u) {
            continue;
        }
        uint64_t start;
        uint64_t end;
        if (!add_overflows_u64(ph[i].p_vaddr, bias, &start) &&
            !add_overflows_u64(start, ph[i].p_memsz, &end) && entry >= start && entry < end) {
            entry_is_executable = true;
            break;
        }
    }
    if (!entry_is_executable) {
        return ELF_LOAD_INVALID;
    }

    uint64_t phdr_vaddr = 0;
    for (uint16_t i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type == PT_PHDR) {
            uint64_t end;
            if (ph[i].p_filesz < phdr_size || add_overflows_u64(ph[i].p_vaddr, bias, &phdr_vaddr) ||
                add_overflows_u64(phdr_vaddr, phdr_size, &end) || end > image_end) {
                return ELF_LOAD_INVALID;
            }
            break;
        }
        if (ph[i].p_type == PT_LOAD && eh->e_phoff >= ph[i].p_offset &&
            phdr_size <= ph[i].p_filesz && eh->e_phoff - ph[i].p_offset <= ph[i].p_filesz - phdr_size) {
            uint64_t delta = eh->e_phoff - ph[i].p_offset;
            uint64_t segment;
            if (!add_overflows_u64(ph[i].p_vaddr, bias, &segment) && !add_overflows_u64(segment, delta, &phdr_vaddr)) {
                break;
            }
        }
    }
    if (phdr_vaddr == 0 || phdr_vaddr < image_start || phdr_vaddr > image_end || phdr_size > image_end - phdr_vaddr) {
        return ELF_LOAD_INVALID;
    }
    bool phdr_is_mapped = false;
    for (uint16_t i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type != PT_LOAD || ph[i].p_memsz == 0) {
            continue;
        }
        uint64_t start;
        uint64_t end;
        if (!add_overflows_u64(ph[i].p_vaddr, bias, &start) &&
            !add_overflows_u64(start, ph[i].p_memsz, &end) && phdr_vaddr >= start && phdr_vaddr <= end &&
            phdr_size <= end - phdr_vaddr) {
            phdr_is_mapped = true;
            break;
        }
    }
    if (!phdr_is_mapped) {
        return ELF_LOAD_INVALID;
    }

    for (uint16_t i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type != PT_LOAD || ph[i].p_memsz == 0) {
            continue;
        }
        uint64_t start;
        uint64_t end;
        uint64_t vaddr;
        if (!load_segment_bounds(&ph[i], bias, &start, &end) || add_overflows_u64(ph[i].p_vaddr, bias, &vaddr)) {
            return ELF_LOAD_INVALID;
        }
        if (vm_space_map_zero(space, start, (size_t)(end - start), page_prot(ph, eh->e_phnum, bias, start)) != 0) {
            return ELF_LOAD_NOMEM;
        }
        if (ph[i].p_filesz != 0 && vm_space_write(space, vaddr, image + ph[i].p_offset, (size_t)ph[i].p_filesz) != 0) {
            return ELF_LOAD_NOMEM;
        }
        if (ph[i].p_memsz > ph[i].p_filesz &&
            vm_space_zero(space, vaddr + ph[i].p_filesz, (size_t)(ph[i].p_memsz - ph[i].p_filesz)) != 0) {
            return ELF_LOAD_NOMEM;
        }
    }

    /* Shared boundary pages need the union of every segment's permissions. */
    for (uint64_t page = image_start; page < image_end; page += VM_PAGE_SIZE) {
        uint32_t prot = page_prot(ph, eh->e_phnum, bias, page);
        if (prot != VM_PROT_NONE && vm_space_mprotect(space, page, VM_PAGE_SIZE, prot) != 0) {
            return ELF_LOAD_NOMEM;
        }
    }

    out->entry = entry;
    out->phdr = phdr_vaddr;
    out->phent = eh->e_phentsize;
    out->phnum = eh->e_phnum;
    out->image_start = image_start;
    out->image_end = image_end;
    out->load_bias = bias;
    out->type = eh->e_type;
    return ELF_LOAD_OK;
}
