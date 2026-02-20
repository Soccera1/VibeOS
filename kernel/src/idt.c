#include "idt.h"

#include <stdint.h>

#include "string.h"

struct idt_entry {
    uint16_t offset_low;
    uint16_t selector;
    uint8_t ist;
    uint8_t type_attr;
    uint16_t offset_mid;
    uint32_t offset_high;
    uint32_t zero;
} __attribute__((packed));

struct idtr {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

static struct idt_entry idt[256];

extern void idt_load(const struct idtr* idtr);

extern void isr0(void);
extern void isr1(void);
extern void isr2(void);
extern void isr3(void);
extern void isr4(void);
extern void isr5(void);
extern void isr6(void);
extern void isr7(void);
extern void isr8(void);
extern void isr9(void);
extern void isr10(void);
extern void isr11(void);
extern void isr12(void);
extern void isr13(void);
extern void isr14(void);
extern void isr15(void);
extern void isr16(void);
extern void isr17(void);
extern void isr18(void);
extern void isr19(void);
extern void isr20(void);
extern void isr21(void);
extern void isr22(void);
extern void isr23(void);
extern void isr24(void);
extern void isr25(void);
extern void isr26(void);
extern void isr27(void);
extern void isr28(void);
extern void isr29(void);
extern void isr30(void);
extern void isr31(void);
extern void isr128(void);

static void idt_set_gate(int vec, void (*handler)(void), uint8_t type_attr, uint8_t ist) {
    uint64_t addr = (uint64_t)(uintptr_t)handler;
    idt[vec].offset_low = (uint16_t)(addr & 0xFFFFu);
    idt[vec].selector = 0x08;
    idt[vec].ist = ist;
    idt[vec].type_attr = type_attr;
    idt[vec].offset_mid = (uint16_t)((addr >> 16) & 0xFFFFu);
    idt[vec].offset_high = (uint32_t)((addr >> 32) & 0xFFFFFFFFu);
    idt[vec].zero = 0;
}

void idt_init(void) {
    memset(idt, 0, sizeof(idt));

    void (*handlers[32])(void) = {
        isr0,  isr1,  isr2,  isr3,  isr4,  isr5,  isr6,  isr7,  isr8,  isr9,  isr10,
        isr11, isr12, isr13, isr14, isr15, isr16, isr17, isr18, isr19, isr20, isr21,
        isr22, isr23, isr24, isr25, isr26, isr27, isr28, isr29, isr30, isr31,
    };

    for (int i = 0; i < 32; ++i) {
        uint8_t ist = (i == 8) ? 1 : 0;
        idt_set_gate(i, handlers[i], 0x8E, ist);
    }

    idt_set_gate(128, isr128, 0xEE, 0);

    struct idtr idtr;
    idtr.limit = (uint16_t)(sizeof(idt) - 1u);
    idtr.base = (uint64_t)(uintptr_t)&idt[0];
    idt_load(&idtr);
}
