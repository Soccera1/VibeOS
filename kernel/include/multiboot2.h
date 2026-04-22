#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MB2_MAGIC 0x36D76289u

struct mb2_tag {
    uint32_t type;
    uint32_t size;
} __attribute__((packed));

struct mb2_tag_module {
    uint32_t type;
    uint32_t size;
    uint32_t mod_start;
    uint32_t mod_end;
    char cmdline[0];
} __attribute__((packed));

struct mb2_framebuffer_info {
    uint64_t addr;
    uint32_t pitch;
    uint32_t width;
    uint32_t height;
    uint8_t bpp;
    uint8_t type;
    uint8_t red_field_position;
    uint8_t red_mask_size;
    uint8_t green_field_position;
    uint8_t green_mask_size;
    uint8_t blue_field_position;
    uint8_t blue_mask_size;
    uint8_t reserved_field_position;
    uint8_t reserved_mask_size;
};

enum {
    MB2_TAG_END = 0,
    MB2_TAG_MODULE = 3,
    MB2_TAG_FRAMEBUFFER = 8,
    MB2_TAG_ACPI_OLD = 14,
    MB2_TAG_ACPI_NEW = 15,
};

const struct mb2_tag_module* mb2_find_module(uint64_t mb2_info, size_t index);
const void* mb2_find_rsdp(uint64_t mb2_info, size_t* rsdp_len);
bool mb2_find_framebuffer(uint64_t mb2_info, struct mb2_framebuffer_info* out);
