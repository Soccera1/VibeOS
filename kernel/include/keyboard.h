#pragma once

#include <stdbool.h>
#include <stdint.h>

enum keyboard_combo_signal {
    KEYBOARD_COMBO_SIGNAL_NONE = 0,
    KEYBOARD_COMBO_SIGNAL_SIGINT = 2,
    KEYBOARD_COMBO_SIGNAL_SIGTSTP = 20,
};

int keyboard_poll_char(void);
int keyboard_read_char_blocking(void);
int keyboard_input_ready(void);
int keyboard_poll_signal(void);
int keyboard_peek_signal(void);
void keyboard_set_application_cursor_keys(bool enabled);
bool keyboard_application_cursor_keys(void);
void keyboard_handle_scancode(uint8_t scancode, bool extended);
