#pragma once

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

enum {
    MB2_TAG_END = 0,
    MB2_TAG_MODULE = 3,
};

const struct mb2_tag_module* mb2_find_first_module(uint64_t mb2_info);
