#include "input.h"

#include "keyboard.h"
#include "serial.h"

static int normalize_input_char(int c) {
    if (c == '\r') {
        return '\n';
    }
    if (c == 0x7f) {  // DEL from many serial terminals for Backspace
        return '\b';
    }
    return c;
}

int input_poll_char(void) {
    int c = serial_pollc();
    if (c >= 0) {
        return normalize_input_char(c);
    }

    c = keyboard_poll_char();
    if (c >= 0) {
        return normalize_input_char(c);
    }

    return -1;
}

int input_read_char_blocking(void) {
    for (;;) {
        int c = input_poll_char();
        if (c >= 0) {
            return c;
        }
        __asm__ volatile("pause");
    }
}
