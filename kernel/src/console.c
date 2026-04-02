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
static uint16_t main_vga[VGA_WIDTH * VGA_HEIGHT];
static size_t cursor_row;
static size_t cursor_col;
static uint8_t color = 0x07;
static uint8_t saved_color;
static size_t saved_cursor_row;
static size_t saved_cursor_col;
static bool alt_mode_active;
static uint8_t ansi_state;  // 0=none, 1=ESC, 2=CSI
static char ansi_buf[32];
static size_t ansi_len;

static void clamp_cursor(void) {
    if (cursor_row >= VGA_HEIGHT) {
        cursor_row = VGA_HEIGHT - 1;
    }
    if (cursor_col >= VGA_WIDTH) {
        cursor_col = VGA_WIDTH - 1;
    }
}

static void update_hw_cursor(void) {
    clamp_cursor();
    size_t row = cursor_row;
    size_t col = cursor_col;
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
    clamp_cursor();
    for (size_t x = cursor_col; x < VGA_WIDTH; ++x) {
        vga[cursor_row * VGA_WIDTH + x] = ((uint16_t)color << 8) | ' ';
    }
}

static void clear_screen_from_cursor(void) {
    clamp_cursor();
    clear_line_from_cursor();

    for (size_t y = cursor_row + 1; y < VGA_HEIGHT; ++y) {
        for (size_t x = 0; x < VGA_WIDTH; ++x) {
            vga[y * VGA_WIDTH + x] = ((uint16_t)color << 8) | ' ';
        }
    }
}

static size_t parse_ansi_params(unsigned* params, size_t max_params, bool* private_mode) {
    size_t count = 0;
    size_t i = 0;
    const size_t seq_len = (ansi_len > 0) ? (ansi_len - 1) : 0;

    if (private_mode != NULL) {
        *private_mode = false;
    }

    if (seq_len > 0 && ansi_buf[0] == '?') {
        if (private_mode != NULL) {
            *private_mode = true;
        }
        i = 1;
    }

    while (i < seq_len) {
        unsigned value = 0u;
        bool have_value = false;

        while (i < seq_len && ansi_buf[i] != ';') {
            char c = ansi_buf[i++];
            if (c >= '0' && c <= '9') {
                have_value = true;
                value = value * 10u + (unsigned)(c - '0');
                continue;
            }
            i = seq_len;
            break;
        }

        if (count < max_params) {
            params[count] = have_value ? value : 0u;
        }
        ++count;

        if (i >= seq_len) {
            break;
        }

        ++i;
        if (i == seq_len) {
            if (count < max_params) {
                params[count] = 0u;
            }
            ++count;
            break;
        }
    }

    return count;
}

static unsigned ansi_param_or_default(const unsigned* params, size_t count, size_t idx, unsigned default_value) {
    if (idx < count) {
        return params[idx];
    }
    return default_value;
}

static void move_cursor_to(unsigned row_1based, unsigned col_1based) {
    if (row_1based == 0u) {
        row_1based = 1u;
    }
    if (col_1based == 0u) {
        col_1based = 1u;
    }

    cursor_row = (size_t)(row_1based - 1u);
    cursor_col = (size_t)(col_1based - 1u);
    clamp_cursor();
}

static void move_cursor_relative(int row_delta, int col_delta) {
    int row = (int)cursor_row + row_delta;
    int col = (int)cursor_col + col_delta;

    if (row < 0) {
        row = 0;
    } else if (row >= (int)VGA_HEIGHT) {
        row = (int)VGA_HEIGHT - 1;
    }

    if (col < 0) {
        col = 0;
    } else if (col >= (int)VGA_WIDTH) {
        col = (int)VGA_WIDTH - 1;
    }

    cursor_row = (size_t)row;
    cursor_col = (size_t)col;
}

static void clear_entire_line(void) {
    clamp_cursor();
    for (size_t x = 0; x < VGA_WIDTH; ++x) {
        vga[cursor_row * VGA_WIDTH + x] = ((uint16_t)color << 8) | ' ';
    }
}

static void clear_line_to_cursor(void) {
    clamp_cursor();
    for (size_t x = 0; x <= cursor_col && x < VGA_WIDTH; ++x) {
        vga[cursor_row * VGA_WIDTH + x] = ((uint16_t)color << 8) | ' ';
    }
}

static void clear_screen_to_cursor(void) {
    clamp_cursor();

    for (size_t y = 0; y < cursor_row; ++y) {
        for (size_t x = 0; x < VGA_WIDTH; ++x) {
            vga[y * VGA_WIDTH + x] = ((uint16_t)color << 8) | ' ';
        }
    }

    for (size_t x = 0; x <= cursor_col && x < VGA_WIDTH; ++x) {
        vga[cursor_row * VGA_WIDTH + x] = ((uint16_t)color << 8) | ' ';
    }
}

static void enter_alt_mode(void) {
    if (alt_mode_active) {
        return;
    }

    for (size_t i = 0; i < VGA_WIDTH * VGA_HEIGHT; ++i) {
        main_vga[i] = vga[i];
    }

    saved_cursor_row = cursor_row;
    saved_cursor_col = cursor_col;
    saved_color = color;
    alt_mode_active = true;
    cursor_row = 0;
    cursor_col = 0;
    for (size_t i = 0; i < VGA_WIDTH * VGA_HEIGHT; ++i) {
        vga[i] = ((uint16_t)color << 8) | ' ';
    }
    update_hw_cursor();
}

static void exit_alt_mode(void) {
    if (!alt_mode_active) {
        return;
    }

    for (size_t i = 0; i < VGA_WIDTH * VGA_HEIGHT; ++i) {
        vga[i] = main_vga[i];
    }

    cursor_row = saved_cursor_row;
    cursor_col = saved_cursor_col;
    color = saved_color;
    alt_mode_active = false;
    update_hw_cursor();
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
            unsigned params[4] = {0, 0, 0, 0};
            bool private_mode = false;
            size_t param_count = parse_ansi_params(params, 4, &private_mode);

            if (c == 'K') {
                unsigned mode = ansi_param_or_default(params, param_count, 0, 0u);
                if (mode == 2u) {
                    clear_entire_line();
                } else if (mode == 1u) {
                    clear_line_to_cursor();
                } else {
                    clear_line_from_cursor();
                }
            } else if (c == 'J') {
                unsigned mode = ansi_param_or_default(params, param_count, 0, 0u);
                if (mode == 2u) {
                    console_clear();
                } else if (mode == 1u) {
                    clear_screen_to_cursor();
                } else {
                    clear_screen_from_cursor();
                }
            } else if (c == 'H' || c == 'f') {
                unsigned row = ansi_param_or_default(params, param_count, 0, 1u);
                unsigned col = ansi_param_or_default(params, param_count, 1, 1u);
                move_cursor_to(row, col);
            } else if (c == 'A') {
                unsigned n = ansi_param_or_default(params, param_count, 0, 1u);
                move_cursor_relative(-(int)n, 0);
            } else if (c == 'B') {
                unsigned n = ansi_param_or_default(params, param_count, 0, 1u);
                move_cursor_relative((int)n, 0);
            } else if (c == 'C') {
                unsigned n = ansi_param_or_default(params, param_count, 0, 1u);
                move_cursor_relative(0, (int)n);
            } else if (c == 'D') {
                unsigned n = ansi_param_or_default(params, param_count, 0, 1u);
                move_cursor_relative(0, -(int)n);
            } else if (c == 'G') {
                unsigned col = ansi_param_or_default(params, param_count, 0, 1u);
                move_cursor_to((unsigned)(cursor_row + 1u), col);
            } else if (c == 's') {
                saved_cursor_row = cursor_row;
                saved_cursor_col = cursor_col;
            } else if (c == 'u') {
                cursor_row = saved_cursor_row;
                cursor_col = saved_cursor_col;
            } else if (c == 'h' && private_mode && param_count > 0 && params[0] == 1049u) {
                enter_alt_mode();
            } else if (c == 'l' && private_mode && param_count > 0 && params[0] == 1049u) {
                exit_alt_mode();
            }
            ansi_state = 0;
            update_hw_cursor();
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

    clamp_cursor();

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
