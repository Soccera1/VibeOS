#include <kernel/idt.h>
#include <kernel/debugcon.h>
#include <stdint.h>

struct registers {
    uint32_t ds;
    uint32_t edi, esi, ebp, esp, ebx, edx, ecx, eax;
    uint32_t int_no, err_code;
    uint32_t eip, cs, eflags, useresp, ss;
} __attribute__((packed));

typedef void (*isr_t)(struct registers*);
static isr_t interrupt_handlers[256];

void register_interrupt_handler(uint8_t n, isr_t handler) {
    interrupt_handlers[n] = handler;
}

void isr_handler(struct registers* regs) {
    if (interrupt_handlers[regs->int_no] != 0) {
        isr_t handler = interrupt_handlers[regs->int_no];
        handler(regs);
    } else {
        print_debugcon("Unhandled Exception: 0x");
        print_hex_debugcon(regs->int_no);
        print_debugcon(" EIP: 0x");
        print_hex_debugcon(regs->eip);
        print_debugcon(" ERR: 0x");
        print_hex_debugcon(regs->err_code);

        if (regs->int_no == 14) { // Page Fault
            uint32_t cr2;
            asm volatile("mov %%cr2, %0" : "=r"(cr2));
            print_debugcon(" ADDR: 0x");
            print_hex_debugcon(cr2);
        }

        print_debugcon(" - Panic!\n");
        while(1) asm volatile("hlt");
    }
}

void irq_handler(struct registers* regs) {
    if (regs->int_no >= 40) {
        asm volatile("outb %%al, $0xA0" :: "a"(0x20));
    }
    asm volatile("outb %%al, $0x20" :: "a"(0x20));

    if (interrupt_handlers[regs->int_no] != 0) {
        isr_t handler = interrupt_handlers[regs->int_no];
        handler(regs);
    }
}
