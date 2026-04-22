#include "keyboard.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "io.h"

static const char keymap[128] = {
    0,   27,  '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\b', '\t',
    'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\r', 0,   'a',  's',
    'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`', 0,   '\\', 'z', 'x', 'c',  'v',
    'b', 'n', 'm', ',', '.', '/', 0,   '*', 0,   ' ', 0,
};

static const char keymap_shift[128] = {
    0,   27,  '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '\b', '\t',
    'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', '\r', 0,   'A',  'S',
    'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', '"', '~', 0,   '|',  'Z', 'X', 'C',  'V',
    'B', 'N', 'M', '<', '>', '?', 0,   '*', 0,   ' ', 0,
};

static int shift_pressed;
static int ctrl_pressed;
static bool extended_scancode;
static char pending_chars[8];
static size_t pending_char_count;

static void enqueue_pending_char(char c) {
    if (pending_char_count < sizeof(pending_chars)) {
        pending_chars[pending_char_count++] = c;
    }
}

static void enqueue_pending_string(const char* s) {
    while (*s != '\0') {
        enqueue_pending_char(*s++);
    }
}

static int dequeue_pending_char(void) {
    if (pending_char_count == 0) {
        return -1;
    }

    int c = (uint8_t)pending_chars[0];
    for (size_t i = 1; i < pending_char_count; ++i) {
        pending_chars[i - 1] = pending_chars[i];
    }
    --pending_char_count;
    return c;
}

static int ctrl_modified_char(char c) {
    if (c >= 'a' && c <= 'z') {
        return (c - 'a') + 1;
    }
    if (c >= 'A' && c <= 'Z') {
        return (c - 'A') + 1;
    }

    switch (c) {
        case ' ':
        case '@':
            return 0;
        case '[':
            return 27;
        case '\\':
            return 28;
        case ']':
            return 29;
        case '^':
            return 30;
        case '_':
        case '/':
            return 31;
        case '?':
            return 127;
        default:
            return (int)c;
    }
}

int keyboard_poll_char(void) {
    int pending = dequeue_pending_char();
    if (pending >= 0) {
        return pending;
    }

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

    if (extended) {
        switch (sc) {
            case 0x48:
                enqueue_pending_string("\x1b[A");
                return dequeue_pending_char();
            case 0x50:
                enqueue_pending_string("\x1b[B");
                return dequeue_pending_char();
            default:
                return -1;
        }
    }

    if (sc >= 128) {
        return -1;
    }

    char c = shift_pressed ? keymap_shift[sc] : keymap[sc];
    if (c == 0) {
        return -1;
    }

    if (!extended && ctrl_pressed) {
        return ctrl_modified_char(c);
    }

    return (int)c;
}

int keyboard_read_char_blocking(void) {
    for (;;) {
        int c = keyboard_poll_char();
        if (c >= 0) {
            return c;
        }
        __asm__ volatile("pause");
    }
}

int keyboard_input_ready(void) {
    return pending_char_count != 0 || (inb(0x64) & 1u) != 0;
}

int keyboard_poll_signal(void) {
    return KEYBOARD_COMBO_SIGNAL_NONE;
}

int keyboard_peek_signal(void) {
    return KEYBOARD_COMBO_SIGNAL_NONE;
}
