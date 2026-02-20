#include "gdt.h"

#include <stdint.h>

#include "string.h"

struct tss64 {
    uint32_t reserved0;
    uint64_t rsp0;
    uint64_t rsp1;
    uint64_t rsp2;
    uint64_t reserved1;
    uint64_t ist1;
    uint64_t ist2;
    uint64_t ist3;
    uint64_t ist4;
    uint64_t ist5;
    uint64_t ist6;
    uint64_t ist7;
    uint64_t reserved2;
    uint16_t reserved3;
    uint16_t io_map_base;
} __attribute__((packed));

static uint64_t gdt[7];
static struct tss64 tss;
static uint8_t df_stack[4096];

extern void gdt_load(const struct gdtr* gdtr, uint16_t code_sel, uint16_t data_sel);
extern void gdt_load_tss(uint16_t selector);

static void set_tss_descriptor(uint16_t selector, uint64_t base, uint32_t limit) {
    const uint64_t access = 0x89ull;
    const uint64_t flags = 0x0ull;

    uint64_t low = 0;
    low |= (uint64_t)(limit & 0xFFFFu);
    low |= (uint64_t)(base & 0xFFFFFFu) << 16;
    low |= access << 40;
    low |= (uint64_t)((limit >> 16) & 0x0Fu) << 48;
    low |= flags << 52;
    low |= (uint64_t)((base >> 24) & 0xFFu) << 56;

    uint64_t high = (base >> 32);

    gdt[selector >> 3] = low;
    gdt[(selector >> 3) + 1] = high;
}

void gdt_init(void) {
    memset(&tss, 0, sizeof(tss));
    tss.io_map_base = sizeof(tss);
    tss.ist1 = (uint64_t)(uintptr_t)(&df_stack[sizeof(df_stack)]);

    gdt[0] = 0x0000000000000000ull;
    gdt[1] = 0x00AF9A000000FFFFull;  // 0x08 kernel code
    gdt[2] = 0x00CF92000000FFFFull;  // 0x10 kernel data
    gdt[3] = 0x00CFF2000000FFFFull;  // 0x18 user data
    gdt[4] = 0x00AFFA000000FFFFull;  // 0x20 user code

    set_tss_descriptor(0x28, (uint64_t)(uintptr_t)&tss, (uint32_t)sizeof(tss) - 1u);

    struct gdtr gdtr;
    gdtr.limit = (uint16_t)(sizeof(gdt) - 1u);
    gdtr.base = (uint64_t)(uintptr_t)&gdt[0];

    gdt_load(&gdtr, 0x08, 0x10);
    gdt_load_tss(0x28);
}

void gdt_set_kernel_stack(uint64_t rsp0) {
    tss.rsp0 = rsp0;
}
