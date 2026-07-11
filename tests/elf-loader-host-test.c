#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elf_loader.h"
#include "vm.h"

#define TEST_IMAGE_SIZE 0x3000u
#define TEST_LOAD_BASE 0x01000000ull
#define REQUIRE(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "requirement failed at %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        abort(); \
    } \
} while (0)

struct test_ehdr {
    uint8_t ident[16];
    uint16_t type;
    uint16_t machine;
    uint32_t version;
    uint64_t entry;
    uint64_t phoff;
    uint64_t shoff;
    uint32_t flags;
    uint16_t ehsize;
    uint16_t phentsize;
    uint16_t phnum;
    uint16_t shentsize;
    uint16_t shnum;
    uint16_t shstrndx;
} __attribute__((packed));

struct test_phdr {
    uint32_t type;
    uint32_t flags;
    uint64_t offset;
    uint64_t vaddr;
    uint64_t paddr;
    uint64_t filesz;
    uint64_t memsz;
    uint64_t align;
} __attribute__((packed));

static uint64_t mapped_pages[8];
static uint32_t mapped_prot[8];
static size_t mapped_count;

static int page_index(uint64_t page) {
    for (size_t i = 0; i < mapped_count; ++i) {
        if (mapped_pages[i] == page) {
            return (int)i;
        }
    }
    return -1;
}

int vm_space_map_zero(struct vm_space* space, uint64_t addr, size_t len, uint32_t prot) {
    (void)space;
    for (uint64_t page = addr; page < addr + len; page += VM_PAGE_SIZE) {
        if (page_index(page) >= 0) {
            continue;
        }
        REQUIRE(mapped_count < sizeof(mapped_pages) / sizeof(mapped_pages[0]));
        mapped_pages[mapped_count] = page;
        mapped_prot[mapped_count] = prot;
        ++mapped_count;
    }
    return 0;
}

int vm_space_write(struct vm_space* space, uint64_t addr, const void* src, size_t len) {
    (void)space;
    (void)src;
    if (len == 0) {
        return 0;
    }
    return page_index(addr & VM_PAGE_MASK) >= 0 && page_index((addr + len - 1u) & VM_PAGE_MASK) >= 0 ? 0 : -1;
}

int vm_space_zero(struct vm_space* space, uint64_t addr, size_t len) {
    return vm_space_write(space, addr, "", len);
}

int vm_space_mprotect(struct vm_space* space, uint64_t addr, size_t len, uint32_t prot) {
    (void)space;
    for (uint64_t page = addr; page < addr + len; page += VM_PAGE_SIZE) {
        int index = page_index(page);
        if (index < 0) {
            return -1;
        }
        mapped_prot[index] = prot;
    }
    return 0;
}

static void make_valid_image(uint8_t image[TEST_IMAGE_SIZE]) {
    memset(image, 0, TEST_IMAGE_SIZE);
    struct test_ehdr* eh = (struct test_ehdr*)image;
    eh->ident[0] = 0x7f;
    eh->ident[1] = 'E';
    eh->ident[2] = 'L';
    eh->ident[3] = 'F';
    eh->ident[4] = 2;
    eh->ident[5] = 1;
    eh->ident[6] = 1;
    eh->type = ELF_ET_DYN;
    eh->machine = 62;
    eh->version = 1;
    eh->entry = 0x1000;
    eh->phoff = sizeof(*eh);
    eh->ehsize = sizeof(*eh);
    eh->phentsize = sizeof(struct test_phdr);
    eh->phnum = 2;

    struct test_phdr* ph = (struct test_phdr*)(image + eh->phoff);
    ph[0].type = 1;
    ph[0].flags = 4;
    ph[0].offset = 0;
    ph[0].vaddr = 0;
    ph[0].filesz = 0x1100;
    ph[0].memsz = 0x1800;
    ph[0].align = 0x1000;
    ph[1].type = 1;
    ph[1].flags = 5;
    ph[1].offset = 0x1000;
    ph[1].vaddr = 0x1000;
    ph[1].filesz = 0x1000;
    ph[1].memsz = 0x1100;
    ph[1].align = 0x1000;
}

static void reset_mappings(void) {
    mapped_count = 0;
    memset(mapped_pages, 0, sizeof(mapped_pages));
    memset(mapped_prot, 0, sizeof(mapped_prot));
}

int main(void) {
    uint8_t image[TEST_IMAGE_SIZE];
    struct vm_space space = {0};
    struct elf_image_info info;

    make_valid_image(image);
    reset_mappings();
    REQUIRE(elf_load_image(&space, image, sizeof(image), 0, &info) == ELF_LOAD_OK);
    REQUIRE(info.type == ELF_ET_DYN);
    REQUIRE(info.entry == TEST_LOAD_BASE + 0x1000);
    REQUIRE(info.phdr == TEST_LOAD_BASE + sizeof(struct test_ehdr));
    REQUIRE(info.image_start == TEST_LOAD_BASE);
    REQUIRE(info.image_end == TEST_LOAD_BASE + 0x3000);
    REQUIRE(mapped_count == 3);
    REQUIRE(mapped_prot[page_index(TEST_LOAD_BASE)] == VM_PROT_READ);
    REQUIRE(mapped_prot[page_index(TEST_LOAD_BASE + 0x1000)] == (VM_PROT_READ | VM_PROT_EXEC));
    REQUIRE(mapped_prot[page_index(TEST_LOAD_BASE + 0x2000)] == (VM_PROT_READ | VM_PROT_EXEC));

    make_valid_image(image);
    struct test_ehdr* eh = (struct test_ehdr*)image;
    struct test_phdr* ph = (struct test_phdr*)(image + sizeof(struct test_ehdr));
    eh->phnum = 3;
    ph[2].type = 3;
    ph[2].offset = 0x200;
    ph[2].filesz = sizeof("/lib/ld-musl-x86_64.so.1");
    memcpy(image + ph[2].offset, "/lib/ld-musl-x86_64.so.1", (size_t)ph[2].filesz);
    reset_mappings();
    REQUIRE(elf_load_image(&space, image, sizeof(image), 0, &info) == ELF_LOAD_OK);
    REQUIRE(info.has_interp);
    REQUIRE(strcmp(info.interp_path, "/lib/ld-musl-x86_64.so.1") == 0);

    image[ph[2].offset] = 'l';
    REQUIRE(elf_load_image(&space, image, sizeof(image), 0, &info) == ELF_LOAD_INVALID);

    make_valid_image(image);
    ((struct test_ehdr*)image)->machine = 3;
    REQUIRE(elf_load_image(&space, image, sizeof(image), 0, &info) == ELF_LOAD_INVALID);

    make_valid_image(image);
    ((struct test_ehdr*)image)->phoff = UINT64_MAX - 8u;
    REQUIRE(elf_load_image(&space, image, sizeof(image), 0, &info) == ELF_LOAD_INVALID);

    make_valid_image(image);
    ph = (struct test_phdr*)(image + sizeof(struct test_ehdr));
    ph[1].filesz = ph[1].memsz + 1u;
    REQUIRE(elf_load_image(&space, image, sizeof(image), 0, &info) == ELF_LOAD_INVALID);

    make_valid_image(image);
    ph = (struct test_phdr*)(image + sizeof(struct test_ehdr));
    ph[1].align = 24;
    REQUIRE(elf_load_image(&space, image, sizeof(image), 0, &info) == ELF_LOAD_INVALID);

    make_valid_image(image);
    ((struct test_ehdr*)image)->entry = 0x2800;
    REQUIRE(elf_load_image(&space, image, sizeof(image), 0, &info) == ELF_LOAD_INVALID);

    puts("ELF loader host tests passed");
    return 0;
}
