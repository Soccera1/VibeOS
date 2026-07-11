#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fs.h"

struct vm_space;

#define ELF_ET_EXEC 2u
#define ELF_ET_DYN 3u

enum elf_load_result {
    ELF_LOAD_OK = 0,
    ELF_LOAD_INVALID = -1,
    ELF_LOAD_NOMEM = -2,
};

struct elf_image_info {
    uint64_t entry;
    uint64_t phdr;
    uint64_t phent;
    uint64_t phnum;
    uint64_t image_start;
    uint64_t image_end;
    uint64_t load_bias;
    uint16_t type;
    bool has_interp;
    char interp_path[FS_MAX_PATH];
};

/* Validate and map one x86-64 ELF image into an inactive userspace VM. */
int elf_load_image(struct vm_space* space, const uint8_t* image, size_t image_size,
                   uint64_t et_dyn_base, struct elf_image_info* out);

