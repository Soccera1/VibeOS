#include <stdint.h>
#include <string.h>

#define BG_COLOR 0xFF1E1E2E
#define FG_COLOR 0xFFFFFFFF

extern const unsigned char font8x16[128][16];

static uint32_t* fb;
static uint32_t fb_width, fb_height, fb_pitch;
static uint32_t cursor_x = 0, cursor_y = 0;

void terminal_draw_cursor(uint32_t color) {
    if (!fb) return;
    if (cursor_x + 8 > fb_width || cursor_y + 16 > fb_height) return;
    for (int i = 14; i < 16; i++) {
        for (int j = 0; j < 8; j++) {
            fb[(cursor_y + i) * fb_pitch + (cursor_x + j)] = color;
        }
    }
}

static void draw_char(unsigned char c, uint32_t x, uint32_t y, uint32_t fg, uint32_t bg) {
    if (!fb || c > 127) return;
    if (x + 8 > fb_width || y + 16 > fb_height) return;
    for (int i = 0; i < 16; i++) {
        uint8_t row = font8x16[c][i];
        for (int j = 0; j < 8; j++) {
            if (row & (1 << (7 - j))) {
                fb[(y + i) * fb_pitch + (x + j)] = fg;
            } else {
                fb[(y + i) * fb_pitch + (x + j)] = bg;
            }
        }
    }
}

void terminal_clear() {
    if (!fb) return;
    for (uint32_t i = 0; i < fb_width * fb_height; i++) fb[i] = BG_COLOR;
    cursor_x = 0;
    cursor_y = 0;
}

void terminal_init(uint32_t* addr, uint32_t w, uint32_t h, uint32_t p) {
    fb = addr;
    fb_width = w;
    fb_height = h;
    fb_pitch = p / 4;
    terminal_clear();
    terminal_draw_cursor(FG_COLOR);
}

void terminal_scroll() {
    for (uint32_t y = 0; y < fb_height - 16; y++) {
        memcpy(&fb[y * fb_pitch], &fb[(y + 16) * fb_pitch], fb_width * 4);
    }
    for (uint32_t y = fb_height - 16; y < fb_height; y++) {
        for (uint32_t x = 0; x < fb_width; x++) {
            fb[y * fb_pitch + x] = BG_COLOR;
        }
    }
}

void terminal_putc(char c) {
    if (!fb) return;
    
    terminal_draw_cursor(BG_COLOR);

    switch (c) {
        case '\n':
            cursor_x = 0;
            cursor_y += 16;
            break;
        case '\r':
            cursor_x = 0;
            break;
        case '\b':
        case 127:
            if (cursor_x >= 8) {
                cursor_x -= 8;
                draw_char(' ', cursor_x, cursor_y, FG_COLOR, BG_COLOR);
            }
            break;
        case '\t':
            cursor_x = (cursor_x + 32) & ~31;
            break;
        default:
            if ((unsigned char)c >= 32 && (unsigned char)c <= 126) {
                if (cursor_x + 8 > fb_width) {
                    cursor_x = 0;
                    cursor_y += 16;
                }
                draw_char(c, cursor_x, cursor_y, FG_COLOR, BG_COLOR);
                cursor_x += 8;
            }
            break;
    }

    if (cursor_x >= fb_width) {
        cursor_x = 0;
        cursor_y += 16;
    }

    if (cursor_y >= fb_height) {
        terminal_scroll();
        cursor_y -= 16;
    }
    terminal_draw_cursor(FG_COLOR);
}

void terminal_write(const char* s) {
    while (*s) terminal_putc(*s++);
}