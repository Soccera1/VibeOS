#include "input_event.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "io.h"
#include "keyboard.h"

#define EVENT_QUEUE_CAPACITY 4096u
#define EV_SYN 0u
#define EV_KEY 1u
#define EV_REL 2u
#define SYN_REPORT 0u
#define REL_X 0u
#define REL_Y 1u
#define BTN_LEFT 0x110u
#define BTN_RIGHT 0x111u
#define BTN_MIDDLE 0x112u
#define MAX_GRAB_OWNERS 16u

struct event_queue {
    struct linux_input_event events[EVENT_QUEUE_CAPACITY];
    size_t head;
    size_t count;
    uint64_t grab_owners[MAX_GRAB_OWNERS];
};

static struct event_queue g_queues[2];
static bool g_extended;
static bool g_mouse_ready;
static uint8_t g_mouse_packet[3];
static size_t g_mouse_packet_size;
static uint8_t g_mouse_buttons;

static void queue_report(enum input_event_device device, const struct linux_input_event* events, size_t event_count) {
    struct event_queue* queue = &g_queues[(unsigned)device];
    if (events == NULL || event_count == 0u || event_count > EVENT_QUEUE_CAPACITY) {
        return;
    }

    /* Evdev consumers treat everything up to SYN_REPORT as one transaction.
     * If space is tight, discard complete old reports rather than exposing a
     * release, motion component, or synchronization marker on its own. */
    while (EVENT_QUEUE_CAPACITY - queue->count < event_count) {
        do {
            struct linux_input_event dropped = queue->events[queue->head];
            queue->head = (queue->head + 1u) % EVENT_QUEUE_CAPACITY;
            --queue->count;
            if (dropped.type == EV_SYN && dropped.code == SYN_REPORT) {
                break;
            }
        } while (queue->count != 0u);
    }

    for (size_t i = 0; i < event_count; ++i) {
        size_t index = (queue->head + queue->count) % EVENT_QUEUE_CAPACITY;
        queue->events[index] = events[i];
        ++queue->count;
    }
}

static uint16_t linux_keycode(uint8_t code, bool extended) {
    if (!extended) {
        return code;
    }
    switch (code) {
        case 0x1c: return 96;  /* keypad enter */
        case 0x1d: return 97;  /* right ctrl */
        case 0x35: return 98;  /* keypad slash */
        case 0x38: return 100; /* right alt */
        case 0x47: return 102; /* home */
        case 0x48: return 103; /* up */
        case 0x49: return 104; /* page up */
        case 0x4b: return 105; /* left */
        case 0x4d: return 106; /* right */
        case 0x4f: return 107; /* end */
        case 0x50: return 108; /* down */
        case 0x51: return 109; /* page down */
        case 0x52: return 110; /* insert */
        case 0x53: return 111; /* delete */
        default: return code;
    }
}

static void handle_keyboard_byte(uint8_t byte) {
    if (byte == 0xe0u) {
        g_extended = true;
        return;
    }
    bool released = (byte & 0x80u) != 0u;
    uint8_t code = byte & 0x7fu;
    struct linux_input_event report[2] = {
        {.type = EV_KEY, .code = linux_keycode(code, g_extended), .value = released ? 0 : 1},
        {.type = EV_SYN, .code = SYN_REPORT, .value = 0},
    };
    queue_report(INPUT_EVENT_KEYBOARD, report, 2u);
    keyboard_handle_scancode(byte, g_extended);
    g_extended = false;
}

static void handle_mouse_packet(void) {
    uint8_t flags = g_mouse_packet[0];
    int32_t dx = (int32_t)g_mouse_packet[1] - ((flags & 0x10u) != 0u ? 256 : 0);
    int32_t raw_dy = (int32_t)g_mouse_packet[2] - ((flags & 0x20u) != 0u ? 256 : 0);
    int32_t dy = -raw_dy;
    uint8_t buttons = flags & 7u;
    if ((flags & 0x40u) != 0u) dx = (flags & 0x10u) != 0u ? -255 : 255;
    if ((flags & 0x80u) != 0u) dy = (flags & 0x20u) != 0u ? 255 : -255;
    struct linux_input_event report[6];
    size_t event_count = 0u;
    if (dx != 0) report[event_count++] = (struct linux_input_event){.type = EV_REL, .code = REL_X, .value = dx};
    if (dy != 0) report[event_count++] = (struct linux_input_event){.type = EV_REL, .code = REL_Y, .value = dy};
    static const uint16_t codes[3] = {BTN_LEFT, BTN_RIGHT, BTN_MIDDLE};
    for (unsigned i = 0; i < 3; ++i) {
        uint8_t mask = (uint8_t)(1u << i);
        if ((buttons & mask) != (g_mouse_buttons & mask)) {
            report[event_count++] = (struct linux_input_event){
                .type = EV_KEY, .code = codes[i], .value = (buttons & mask) != 0u ? 1 : 0,
            };
        }
    }
    g_mouse_buttons = buttons;
    report[event_count++] = (struct linux_input_event){.type = EV_SYN, .code = SYN_REPORT, .value = 0};
    queue_report(INPUT_EVENT_POINTER, report, event_count);
}

static void handle_mouse_byte(uint8_t byte) {
    if (g_mouse_packet_size == 0u && (byte & 0x08u) == 0u) {
        return;
    }
    g_mouse_packet[g_mouse_packet_size++] = byte;
    if (g_mouse_packet_size == 3u) {
        handle_mouse_packet();
        g_mouse_packet_size = 0u;
    }
}

static bool wait_input_clear(void) {
    for (unsigned i = 0; i < 100000u; ++i) {
        if ((inb(0x64) & 2u) == 0u) return true;
        __asm__ volatile("pause");
    }
    return false;
}

static bool wait_output_full(void) {
    for (unsigned i = 0; i < 100000u; ++i) {
        if ((inb(0x64) & 1u) != 0u) return true;
        __asm__ volatile("pause");
    }
    return false;
}

static bool mouse_command(uint8_t command) {
    if (!wait_input_clear()) return false;
    outb(0x64, 0xd4u);
    if (!wait_input_clear()) return false;
    outb(0x60, command);
    if (!wait_output_full()) return false;
    return inb(0x60) == 0xfau;
}

void input_event_init(void) {
    if (!wait_input_clear()) return;
    outb(0x64, 0xa8u); /* enable auxiliary port */
    if (!wait_input_clear()) return;
    outb(0x64, 0x20u);
    if (!wait_output_full()) return;
    uint8_t config = inb(0x60);
    config &= (uint8_t)~0x20u;
    if (!wait_input_clear()) return;
    outb(0x64, 0x60u);
    if (!wait_input_clear()) return;
    outb(0x60, config);
    if (!mouse_command(0xf6u)) return;
    g_mouse_ready = mouse_command(0xf4u);
}

void input_event_poll(void) {
    while ((inb(0x64) & 1u) != 0u) {
        uint8_t status = inb(0x64);
        uint8_t byte = inb(0x60);
        if ((status & 0x20u) != 0u) {
            if (g_mouse_ready) handle_mouse_byte(byte);
        } else {
            handle_keyboard_byte(byte);
        }
    }
}

bool input_event_ready(enum input_event_device device) {
    input_event_poll();
    return g_queues[(unsigned)device].count != 0u;
}

size_t input_event_read(enum input_event_device device, struct linux_input_event* events, size_t capacity) {
    input_event_poll();
    struct event_queue* queue = &g_queues[(unsigned)device];
    size_t count = 0;
    while (count < capacity && queue->count != 0u) {
        events[count++] = queue->events[queue->head];
        queue->head = (queue->head + 1u) % EVENT_QUEUE_CAPACITY;
        --queue->count;
    }
    return count;
}

bool input_event_grab(enum input_event_device device, uint64_t owner) {
    struct event_queue* queue = &g_queues[(unsigned)device];
    if (owner == 0u) return false;
    for (size_t i = 0; i < MAX_GRAB_OWNERS; ++i) {
        if (queue->grab_owners[i] == owner) return true;
    }
    for (size_t i = 0; i < MAX_GRAB_OWNERS; ++i) {
        if (queue->grab_owners[i] == 0u) {
            queue->grab_owners[i] = owner;
            return true;
        }
    }
    return false;
}

void input_event_ungrab(enum input_event_device device, uint64_t owner) {
    struct event_queue* queue = &g_queues[(unsigned)device];
    for (size_t i = 0; i < MAX_GRAB_OWNERS; ++i) {
        if (queue->grab_owners[i] == owner) {
            queue->grab_owners[i] = 0u;
            return;
        }
    }
}

bool input_event_is_grabbed(enum input_event_device device) {
    const struct event_queue* queue = &g_queues[(unsigned)device];
    for (size_t i = 0; i < MAX_GRAB_OWNERS; ++i) {
        if (queue->grab_owners[i] != 0u) return true;
    }
    return false;
}
