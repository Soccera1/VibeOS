#include "input.h"

#include <stddef.h>

#include "keyboard.h"
#include "serial.h"

#define INPUT_RESPONSE_QUEUE_CAPACITY 64

static char response_queue[INPUT_RESPONSE_QUEUE_CAPACITY];
static size_t response_head;
static size_t response_count;

static int dequeue_response_char(void) {
    if (response_count == 0) {
        return -1;
    }

    int c = (unsigned char)response_queue[response_head];
    response_head = (response_head + 1u) % INPUT_RESPONSE_QUEUE_CAPACITY;
    --response_count;
    return c;
}

static int normalize_input_char(int c) {
    if (c == '\n') {
        return '\r';
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

    int response = dequeue_response_char();
    if (response >= 0) {
        return response;
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

int input_char_ready(void) {
    return response_count != 0 || serial_input_ready() || keyboard_input_ready();
}

int input_poll_signal(void) {
    return keyboard_poll_signal();
}

int input_peek_signal(void) {
    return keyboard_peek_signal();
}

void input_enqueue_response_char(char c) {
    if (response_count >= INPUT_RESPONSE_QUEUE_CAPACITY) {
        return;
    }

    size_t idx = (response_head + response_count) % INPUT_RESPONSE_QUEUE_CAPACITY;
    response_queue[idx] = c;
    ++response_count;
}

void input_enqueue_response_string(const char* s) {
    while (*s != '\0') {
        input_enqueue_response_char(*s++);
    }
}
