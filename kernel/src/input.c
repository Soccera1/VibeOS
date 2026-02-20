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
    if (keyboard_peek_signal() != KEYBOARD_COMBO_SIGNAL_NONE) {
        return -1;
    }

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
        if (keyboard_peek_signal() != KEYBOARD_COMBO_SIGNAL_NONE) {
            return -1;
        }

        int c = input_poll_char();
        if (c >= 0) {
            return c;
        }
        __asm__ volatile("pause");
    }
}

int input_poll_signal(void) {
    return keyboard_poll_signal();
}

int input_peek_signal(void) {
    return keyboard_peek_signal();
}
