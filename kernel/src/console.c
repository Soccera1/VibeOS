#include "console.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

#include "io.h"
#include "serial.h"
#include "string.h"

#define VGA_WIDTH 80
#define VGA_HEIGHT 25
#define VGA_CRTC_INDEX 0x3D4
#define VGA_CRTC_DATA 0x3D5

static volatile uint16_t* const vga = (volatile uint16_t*)0xB8000;
static size_t cursor_row;
static size_t cursor_col;
static uint8_t color = 0x07;
static uint8_t ansi_state;  // 0=none, 1=ESC, 2=CSI
static char ansi_buf[32];
static size_t ansi_len;

static void update_hw_cursor(void) {
    size_t row = cursor_row;
    size_t col = cursor_col;
    if (row >= VGA_HEIGHT) {
        row = VGA_HEIGHT - 1;
    }
    if (col >= VGA_WIDTH) {
        col = VGA_WIDTH - 1;
    }

    uint16_t pos = (uint16_t)(row * VGA_WIDTH + col);
    outb(VGA_CRTC_INDEX, 0x0F);
    outb(VGA_CRTC_DATA, (uint8_t)(pos & 0xFFu));
    outb(VGA_CRTC_INDEX, 0x0E);
    outb(VGA_CRTC_DATA, (uint8_t)((pos >> 8) & 0xFFu));
}

static void scroll_if_needed(void) {
    if (cursor_row < VGA_HEIGHT) {
        return;
    }

    for (size_t y = 1; y < VGA_HEIGHT; ++y) {
        for (size_t x = 0; x < VGA_WIDTH; ++x) {
            vga[(y - 1) * VGA_WIDTH + x] = vga[y * VGA_WIDTH + x];
        }
    }

    for (size_t x = 0; x < VGA_WIDTH; ++x) {
        vga[(VGA_HEIGHT - 1) * VGA_WIDTH + x] = ((uint16_t)color << 8) | ' ';
    }

    cursor_row = VGA_HEIGHT - 1;
}

static void clear_line_from_cursor(void) {
    for (size_t x = cursor_col; x < VGA_WIDTH; ++x) {
        vga[cursor_row * VGA_WIDTH + x] = ((uint16_t)color << 8) | ' ';
    }
}

static void clear_screen_from_cursor(void) {
    clear_line_from_cursor();
    for (size_t y = cursor_row + 1; y < VGA_HEIGHT; ++y) {
        for (size_t x = 0; x < VGA_WIDTH; ++x) {
            vga[y * VGA_WIDTH + x] = ((uint16_t)color << 8) | ' ';
        }
    }
}

static unsigned parse_ansi_param0(void) {
    unsigned v = 0;
    bool any = false;
    for (size_t i = 0; i < ansi_len; ++i) {
        char c = ansi_buf[i];
        if (c >= '0' && c <= '9') {
            any = true;
            v = v * 10u + (unsigned)(c - '0');
            continue;
        }
        if (c == ';') {
            break;
        }
    }
    return any ? v : 0u;
}

static bool handle_ansi_char(char c) {
    if (ansi_state == 0) {
        if ((unsigned char)c == 0x1B) {
            ansi_state = 1;
            ansi_len = 0;
            return true;
        }
        return false;
    }

    if (ansi_state == 1) {
        if (c == '[') {
            ansi_state = 2;
            ansi_len = 0;
            return true;
        }
        ansi_state = 0;
        return true;
    }

    if (ansi_state == 2) {
        if (ansi_len + 1 < sizeof(ansi_buf)) {
            ansi_buf[ansi_len++] = c;
        }

        if ((unsigned char)c >= 0x40u && (unsigned char)c <= 0x7Eu) {
            unsigned p0 = parse_ansi_param0();
            if (c == 'K') {
                clear_line_from_cursor();
            } else if (c == 'J') {
                if (p0 == 2u) {
                    console_clear();
                } else {
                    clear_screen_from_cursor();
                }
            }
            ansi_state = 0;
        }
        return true;
    }

    ansi_state = 0;
    return false;
}

void console_init(void) {
    serial_init();
    console_clear();
}

void console_set_color(unsigned fg, unsigned bg) {
    color = (uint8_t)(((bg & 0x0F) << 4) | (fg & 0x0F));
}

void console_clear(void) {
    cursor_row = 0;
    cursor_col = 0;
    for (size_t i = 0; i < VGA_WIDTH * VGA_HEIGHT; ++i) {
        vga[i] = ((uint16_t)color << 8) | ' ';
    }
    update_hw_cursor();
}

void console_putc(char c) {
    if (handle_ansi_char(c)) {
        return;
    }

    if (c == '\n') {
        serial_putc('\r');
        serial_putc('\n');
        cursor_col = 0;
        ++cursor_row;
        scroll_if_needed();
        update_hw_cursor();
        return;
    }

    if (c == '\r') {
        cursor_col = 0;
        serial_putc('\r');
        update_hw_cursor();
        return;
    }

    if (c == '\b') {
        if (cursor_col > 0) {
            --cursor_col;
            vga[cursor_row * VGA_WIDTH + cursor_col] = ((uint16_t)color << 8) | ' ';
        }
        serial_putc('\b');
        serial_putc(' ');
        serial_putc('\b');
        update_hw_cursor();
        return;
    }

    serial_putc(c);
    vga[cursor_row * VGA_WIDTH + cursor_col] = ((uint16_t)color << 8) | (uint8_t)c;
    ++cursor_col;
    if (cursor_col >= VGA_WIDTH) {
        cursor_col = 0;
        ++cursor_row;
        scroll_if_needed();
    }
    update_hw_cursor();
}

void console_write(const char* s) {
    while (*s != '\0') {
        console_putc(*s++);
    }
}

void console_writen(const char* s, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        console_putc(s[i]);
    }
}

static void print_unsigned(uint64_t value, unsigned base) {
    char buf[32];
    size_t idx = 0;

    if (value == 0) {
        console_putc('0');
        return;
    }

    while (value > 0) {
        unsigned digit = (unsigned)(value % base);
        buf[idx++] = (char)(digit < 10 ? ('0' + digit) : ('a' + (digit - 10)));
        value /= base;
    }

    while (idx > 0) {
        console_putc(buf[--idx]);
    }
}

void console_printf(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);

    while (*fmt != '\0') {
        if (*fmt != '%') {
            console_putc(*fmt++);
            continue;
        }

        ++fmt;
        switch (*fmt) {
            case '%':
                console_putc('%');
                break;
            case 'c':
                console_putc((char)va_arg(ap, int));
                break;
            case 's': {
                const char* s = va_arg(ap, const char*);
                if (s == NULL) {
                    s = "(null)";
                }
                console_write(s);
                break;
            }
            case 'd': {
                int v = va_arg(ap, int);
                if (v < 0) {
                    console_putc('-');
                    print_unsigned((uint64_t)(-v), 10);
                } else {
                    print_unsigned((uint64_t)v, 10);
                }
                break;
            }
            case 'u':
                print_unsigned((uint64_t)va_arg(ap, unsigned), 10);
                break;
            case 'x':
            case 'p':
                print_unsigned((uint64_t)va_arg(ap, uint64_t), 16);
                break;
            default:
                console_putc('?');
                break;
        }
        ++fmt;
    }

    va_end(ap);
}
