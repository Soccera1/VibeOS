#include "multiboot2.h"

static const struct mb2_tag* mb2_first_tag(uint64_t mb2_info) {
    if (mb2_info == 0) {
        return 0;
    }
    return (const struct mb2_tag*)(uintptr_t)(mb2_info + 8);
}

static const struct mb2_tag* mb2_next_tag(const struct mb2_tag* tag) {
    return (const struct mb2_tag*)((const uint8_t*)tag + ((tag->size + 7u) & ~7u));
}

const struct mb2_tag_module* mb2_find_module(uint64_t mb2_info, size_t index) {
    size_t current = 0;
    for (const struct mb2_tag* tag = mb2_first_tag(mb2_info); tag != 0; tag = mb2_next_tag(tag)) {
        if (tag->type == MB2_TAG_END) {
            return 0;
        }
        if (tag->type == MB2_TAG_MODULE && current++ == index) {
            return (const struct mb2_tag_module*)tag;
        }
    }
    return 0;
}

const void* mb2_find_rsdp(uint64_t mb2_info, size_t* rsdp_len) {
    const struct mb2_tag* best = 0;

    for (const struct mb2_tag* tag = mb2_first_tag(mb2_info); tag != 0; tag = mb2_next_tag(tag)) {
        if (tag->type == MB2_TAG_END) {
            break;
        }
        if (tag->type == MB2_TAG_ACPI_NEW) {
            best = tag;
            break;
        }
        if (tag->type == MB2_TAG_ACPI_OLD) {
            best = tag;
        }
    }

    if (best == 0 || best->size <= sizeof(*best)) {
        return 0;
    }

    if (rsdp_len != 0) {
        *rsdp_len = (size_t)(best->size - sizeof(*best));
    }
    return (const uint8_t*)best + sizeof(*best);
}
