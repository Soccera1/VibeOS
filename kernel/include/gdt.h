#pragma once

#include <stdint.h>

struct gdtr {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

void gdt_init(void);
void gdt_set_kernel_stack(uint64_t rsp0);
