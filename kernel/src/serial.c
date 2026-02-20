#include "io.h"
#include "serial.h"

#define COM1 0x3F8

static int serial_ready(void) {
    return (inb(COM1 + 5) & 0x20) != 0;
}

void serial_init(void) {
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x80);
    outb(COM1 + 0, 0x03);
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03);
    outb(COM1 + 2, 0xC7);
    outb(COM1 + 4, 0x0B);
}

void serial_putc(char c) {
    while (!serial_ready()) {
    }
    outb(COM1 + 0, (unsigned char)c);
}

void serial_write(const char* s) {
    while (*s != '\0') {
        if (*s == '\n') {
            serial_putc('\r');
        }
        serial_putc(*s++);
    }
}

int serial_pollc(void) {
    if ((inb(COM1 + 5) & 0x01) == 0) {
        return -1;
    }
    return inb(COM1 + 0);
}
