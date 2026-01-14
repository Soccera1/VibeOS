#include <kernel/idt.h>
#include <string.h>

struct idt_entry idt[256];
struct idt_ptr idtp;

extern void idt_load(uint32_t);

void idt_set_gate(uint8_t num, uint32_t base, uint16_t sel, uint8_t flags) {
    idt[num].base_lo = base & 0xFFFF;
    idt[num].base_hi = (base >> 16) & 0xFFFF;
    idt[num].sel = sel;
    idt[num].always0 = 0;
    idt[num].flags = flags;
}

// Macro to avoid massive repetition
#define SET_ISR(n) extern void isr##n(); idt_set_gate(n, (uint32_t)isr##n, 0x08, 0x8E);
#define SET_IRQ(n, i) extern void irq##n(); idt_set_gate(i, (uint32_t)irq##n, 0x08, 0x8E);

void idt_init() {
    idtp.limit = (sizeof(struct idt_entry) * 256) - 1;
    idtp.base = (uint32_t)&idt;
    memset(&idt, 0, sizeof(struct idt_entry) * 256);

    SET_ISR(0); SET_ISR(1); SET_ISR(2); SET_ISR(3);
    SET_ISR(4); SET_ISR(5); SET_ISR(6); SET_ISR(7);
    SET_ISR(8); SET_ISR(9); SET_ISR(10); SET_ISR(11);
    SET_ISR(12); SET_ISR(13); SET_ISR(14); SET_ISR(15);
    SET_ISR(16); SET_ISR(17); SET_ISR(18); SET_ISR(19);
    SET_ISR(20); SET_ISR(21); SET_ISR(22); SET_ISR(23);
    SET_ISR(24); SET_ISR(25); SET_ISR(26); SET_ISR(27);
    SET_ISR(28); SET_ISR(29); SET_ISR(30); SET_ISR(31);

    SET_IRQ(0, 32); SET_IRQ(1, 33); SET_IRQ(2, 34); SET_IRQ(3, 35);
    SET_IRQ(4, 36); SET_IRQ(5, 37); SET_IRQ(6, 38); SET_IRQ(7, 39);
    SET_IRQ(8, 40); SET_IRQ(9, 41); SET_IRQ(10, 42); SET_IRQ(11, 43);
    SET_IRQ(12, 44); SET_IRQ(13, 45); SET_IRQ(14, 46); SET_IRQ(15, 47);

    extern void syscall_stub();
    idt_set_gate(0x80, (uint32_t)syscall_stub, 0x08, 0xEF); 

    idt_load((uint32_t)&idtp);
}