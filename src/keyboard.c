#include <stdint.h>
#include <kernel/io.h>
#include <kernel/debugcon.h>

#define KBD_DATA 0x60

static char kbd_us[128] = {
    0,  27, '1', '2', '3', '4', '5', '6', '7', '8',	'9', '0', '-', '=', '\b',
    '\t', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n',
    0, 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`', 0, '\\',
    'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 0, '*', 0, ' ', 0
};

static char kbd_us_shift[128] = {
    0,  27, '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '\b',
    '\t', 'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', '\n',
    0, 'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', '"', '~', 0, '|',
    'Z', 'X', 'C', 'V', 'B', 'N', 'M', '<', '>', '?', 0, '*', 0, ' ', 0
};

static volatile int shift_active = 0;
static volatile char input_queue[256];
static volatile uint8_t q_head = 0;
static volatile uint8_t q_tail = 0;

struct registers;
typedef void (*isr_t)(struct registers*);
extern void register_interrupt_handler(uint8_t n, isr_t handler);

void keyboard_callback(struct registers* regs) {
    (void)regs;
    uint8_t scancode = inb(KBD_DATA);

    if (scancode == 0x2A || scancode == 0x36) {
        shift_active = 1;
        return;
    }
    if (scancode == 0xAA || scancode == 0xB6) {
        shift_active = 0;
        return;
    }

    if (scancode & 0x80) return;

    char c = shift_active ? kbd_us_shift[scancode] : kbd_us[scancode];
    if (c) {
        input_queue[q_head++] = c;
    }
}

void keyboard_init() {
    register_interrupt_handler(33, keyboard_callback);
}

char keyboard_getc() {
    while (q_head == q_tail) {
        asm volatile("hlt");
    }
    return input_queue[q_tail++];
}