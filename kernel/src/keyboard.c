#include "keyboard.h"

#include <stdbool.h>
#include <stdint.h>

#include "io.h"

static const char keymap[128] = {
    0,   27,  '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\b', '\t',
    'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n', 0,   'a',  's',
    'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`', 0,   '\\', 'z', 'x', 'c',  'v',
    'b', 'n', 'm', ',', '.', '/', 0,   '*', 0,   ' ', 0,
};

static const char keymap_shift[128] = {
    0,   27,  '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '\b', '\t',
    'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', '\n', 0,   'A',  'S',
    'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', '"', '~', 0,   '|',  'Z', 'X', 'C',  'V',
    'B', 'N', 'M', '<', '>', '?', 0,   '*', 0,   ' ', 0,
};

static int shift_pressed;
static int ctrl_pressed;
static bool extended_scancode;
static int pending_signal;

static void keyboard_queue_signal(int signal) {
    if (signal <= 0 || pending_signal != KEYBOARD_COMBO_SIGNAL_NONE) {
        return;
    }
    pending_signal = signal;
}

int keyboard_poll_char(void) {
    if ((inb(0x64) & 1u) == 0) {
        return -1;
    }

    uint8_t sc = inb(0x60);
    if (sc == 0xE0) {
        extended_scancode = true;
        return -1;
    }

    bool extended = extended_scancode;
    extended_scancode = false;

    if (sc == 0x1D) {
        ctrl_pressed = 1;
        return -1;
    }
    if (sc == 0x9D) {
        ctrl_pressed = 0;
        return -1;
    }

    if (sc == 0x2A || sc == 0x36) {
        shift_pressed = 1;
        return -1;
    }
    if (sc == 0xAA || sc == 0xB6) {
        shift_pressed = 0;
        return -1;
    }

    if ((sc & 0x80u) != 0) {
        return -1;
    }

    if (!extended && ctrl_pressed) {
        if (sc == 0x2E) {
            keyboard_queue_signal(KEYBOARD_COMBO_SIGNAL_SIGINT);
            return -1;
        }
        if (sc == 0x2C) {
            keyboard_queue_signal(KEYBOARD_COMBO_SIGNAL_SIGTSTP);
            return -1;
        }
    }

    if (sc >= 128) {
        return -1;
    }

    char c = shift_pressed ? keymap_shift[sc] : keymap[sc];
    if (c == '\r') {
        c = '\n';
    }

    if (c == 0) {
        return -1;
    }

    return (int)c;
}

int keyboard_read_char_blocking(void) {
    for (;;) {
        if (pending_signal != KEYBOARD_COMBO_SIGNAL_NONE) {
            return -1;
        }

        int c = keyboard_poll_char();
        if (c >= 0) {
            return c;
        }
        __asm__ volatile("pause");
    }
}

int keyboard_poll_signal(void) {
    int signal = pending_signal;
    pending_signal = KEYBOARD_COMBO_SIGNAL_NONE;
    return signal;
}

int keyboard_peek_signal(void) {
    return pending_signal;
}
