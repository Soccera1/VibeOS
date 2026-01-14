#include <kernel/io.h>
#include <stdint.h>

void pic_remap(int offset1, int offset2) {
    uint8_t a1, a2;

    a1 = inb(0x21);                        // save masks
    a2 = inb(0xA1);

    outb(0x20, 0x11);                      // start initialization
    outb(0xA0, 0x11);
    outb(0x21, offset1);                   // ICW2: Master PIC vector offset
    outb(0xA1, offset2);                   // ICW2: Slave PIC vector offset
    outb(0x21, 0x04);                      // ICW3: tell Master PIC there is a slave PIC at IRQ2
    outb(0xA1, 0x02);                      // ICW3: tell Slave PIC its cascade identity
    outb(0x21, 0x01);                      // ICW4: have the PICs use 8086 mode (and not 8080 mode)
    outb(0xA1, 0x01);

    outb(0x21, 0xFC);                      // Unmask IRQ 0 (Timer) and IRQ 1 (Keyboard)
    outb(0xA1, 0xFF);                      // Mask all on slave
}
