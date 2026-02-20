#pragma once

enum keyboard_combo_signal {
    KEYBOARD_COMBO_SIGNAL_NONE = 0,
    KEYBOARD_COMBO_SIGNAL_SIGINT = 2,
    KEYBOARD_COMBO_SIGNAL_SIGTSTP = 20,
};

int keyboard_poll_char(void);
int keyboard_read_char_blocking(void);
int keyboard_poll_signal(void);
int keyboard_peek_signal(void);
