#ifndef DEBUGCON_H
#define DEBUGCON_H

#include <kernel/io.h>

static inline void print_debugcon(const char* s) {
    while (*s) {
        outb(0xe9, *s++);
    }
}

static inline void print_hex_debugcon(uint32_t n) {
    const char* hex = "0123456789ABCDEF";
    for (int i = 28; i >= 0; i -= 4) {
        outb(0xe9, hex[(n >> i) & 0xF]);
    }
}

#endif