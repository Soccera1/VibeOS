#include <stdio.h>

#include "../kernel/src/input_event.c"
#include "../kernel/src/serial.c"

static unsigned keyboard_bytes;

void keyboard_handle_scancode(uint8_t scancode, bool extended) {
    (void)scancode;
    (void)extended;
    ++keyboard_bytes;
}

int main(void) {
    handle_keyboard_byte(0x1eu);
#ifdef CONFIG_KERNEL_PS2_KEYBOARD
    if (keyboard_bytes != 1u) return 1;
#else
    if (keyboard_bytes != 0u) return 1;
#endif
#if defined(CONFIG_KERNEL_INPUT_EVENTS) && defined(CONFIG_KERNEL_PS2_KEYBOARD)
    if (g_queues[INPUT_EVENT_KEYBOARD].count != 2u) return 1;
#else
    if (g_queues[INPUT_EVENT_KEYBOARD].count != 0u) return 1;
#endif
    /* Disabled hardware paths must return without executing port I/O. */
#ifndef CONFIG_KERNEL_PS2_MOUSE
    input_event_init();
    if (g_mouse_ready) return 1;
#endif
#if !defined(CONFIG_KERNEL_PS2_KEYBOARD) && !defined(CONFIG_KERNEL_PS2_MOUSE)
    input_event_poll();
#endif
#if !defined(CONFIG_KERNEL_SERIAL_CONSOLE) && !defined(CONFIG_KERNEL_SERIAL_INPUT)
    serial_init();
#endif
#ifndef CONFIG_KERNEL_SERIAL_CONSOLE
    serial_write("disabled output");
#endif
#ifndef CONFIG_KERNEL_SERIAL_INPUT
    if (serial_input_ready() != 0 || serial_pollc() != -1) return 1;
#endif
    puts("kernel input config checks passed");
    return 0;
}
