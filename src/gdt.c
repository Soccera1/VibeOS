#include <kernel/gdt.h>
#include <string.h>

struct gdt_entry gdt[6];
struct gdt_ptr gp;
struct tss_entry tss;

extern void gdt_flush(uint32_t);
extern void tss_flush();

void gdt_set_gate(int num, uint32_t base, uint32_t limit, uint8_t access, uint8_t gran) {
    gdt[num].base_low = (base & 0xFFFF);
    gdt[num].base_middle = (base >> 16) & 0xFF;
    gdt[num].base_high = (base >> 24) & 0xFF;
    gdt[num].limit_low = (limit & 0xFFFF);
    gdt[num].granularity = ((limit >> 16) & 0x0F) | (gran & 0xF0);
    gdt[num].access = access;
}

void write_tss(int num, uint16_t ss0, uint32_t esp0) {
    uint32_t base = (uint32_t)&tss;
    uint32_t limit = base + sizeof(tss);

    gdt_set_gate(num, base, limit, 0xE9, 0x00);
    memset(&tss, 0, sizeof(tss));

    tss.ss0 = ss0;
    tss.esp0 = esp0;
    tss.cs = 0x08 | 0x03;
    tss.ss = tss.ds = tss.es = tss.fs = tss.gs = 0x10 | 0x03;
}

void set_kernel_stack(uint32_t stack) {
    tss.esp0 = stack;
}

void gdt_init() {
    gp.limit = (sizeof(struct gdt_entry) * 6) - 1;
    gp.base = (uint32_t)&gdt;

    gdt_set_gate(0, 0, 0, 0, 0);                // Null segment
    gdt_set_gate(1, 0, 0xFFFFFFFF, 0x9A, 0xCF); // Kernel Code
    gdt_set_gate(2, 0, 0xFFFFFFFF, 0x92, 0xCF); // Kernel Data
    gdt_set_gate(3, 0, 0xFFFFFFFF, 0xFA, 0xCF); // User Code
    gdt_set_gate(4, 0, 0xFFFFFFFF, 0xF2, 0xCF); // User Data
    write_tss(5, 0x10, 0x0);                    // TSS (esp0 set on task switch)

    gdt_flush((uint32_t)&gp);
    tss_flush();
}