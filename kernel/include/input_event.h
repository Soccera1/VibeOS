#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum input_event_device {
    INPUT_EVENT_POINTER = 0,
    INPUT_EVENT_KEYBOARD = 1,
};

struct linux_input_event {
    int64_t tv_sec;
    int64_t tv_usec;
    uint16_t type;
    uint16_t code;
    int32_t value;
};

void input_event_init(void);
void input_event_poll(void);
bool input_event_ready(enum input_event_device device);
size_t input_event_read(enum input_event_device device, struct linux_input_event* events, size_t capacity);
bool input_event_grab(enum input_event_device device, uint64_t owner);
void input_event_ungrab(enum input_event_device device, uint64_t owner);
bool input_event_is_grabbed(enum input_event_device device);
